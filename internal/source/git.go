package source

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sekscan/internal/store"
)

// git runs noninteractively. Tokens live only in the child environment, never
// command arguments or repository configuration. Raw Git diagnostics may contain
// credentials and are deliberately not returned.
func (c *Client) git(ctx context.Context, dir string, args ...string) ([]byte, error) {
	if c.GitCommand != nil {
		return c.GitCommand(ctx, dir, args...)
	}
	cmd := exec.CommandContext(ctx, "git", append([]string{
		"-c", "core.hooksPath=/dev/null", "-c", "credential.helper=",
		"-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
		"-c", "http.followRedirects=false", "-c", "submodule.recurse=false",
	}, args...)...)
	cmd.Dir = dir
	for _, env := range os.Environ() {
		key := strings.SplitN(env, "=", 2)[0]
		if !strings.HasPrefix(key, "GIT_") && key != "GITHUB_TOKEN" && key != "GH_TOKEN" {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_LFS_SKIP_SMUDGE=1")
	if c.Token != "" {
		auth := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + c.Token))
		cmd.Env = append(cmd.Env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.https://github.com/.extraheader", "GIT_CONFIG_VALUE_0=Authorization: Basic "+auth)
	}
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if _, ok := err.(*exec.Error); ok {
			return nil, fmt.Errorf("Git is required for online GitHub scans; install git and ensure it is on PATH")
		}
		return nil, fmt.Errorf("git %s failed; check repository/ref access, token permissions, network connectivity, and cached checkout state", args[0])
	}
	return out, nil
}

func (c *Client) prepareGit(ctx context.Context, repo Repository, ref, root string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	lockPath := filepath.Join(root, "git.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", "", fmt.Errorf("repository cache is being updated; retry after the other operation completes")
	}
	lock.Close()
	defer os.Remove(lockPath)
	checkout := filepath.Join(root, "repository")
	if _, err = os.Lstat(checkout); os.IsNotExist(err) {
		tmp, err := os.MkdirTemp(root, "clone-")
		if err != nil {
			return "", "", err
		}
		defer os.RemoveAll(tmp)
		// No checkout during clone: the scanner never needs Git history in its
		// input, and no smudge filters or repository hooks should run.
		if _, err = c.git(ctx, "", "clone", "--no-checkout", "--origin", "origin", "--", repo.URL()+".git", tmp); err != nil {
			return "", "", err
		}
		if _, err = c.git(ctx, tmp, "reset", "--hard", "HEAD"); err != nil {
			return "", "", err
		}
		if err = os.Rename(tmp, checkout); err != nil {
			return "", "", err
		}
	} else if err != nil {
		return "", "", err
	} else {
		origin, err := c.git(ctx, checkout, "remote", "get-url", "origin")
		if err != nil || strings.TrimSpace(string(origin)) != repo.URL()+".git" {
			return "", "", fmt.Errorf("cached repository origin does not match requested GitHub repository")
		}
		status, err := c.git(ctx, checkout, "status", "--porcelain")
		if err != nil {
			return "", "", err
		}
		if len(status) != 0 {
			return "", "", fmt.Errorf("cached repository has local changes; move or clean the checkout before retrying")
		}
		if _, err = c.git(ctx, checkout, "pull", "--ff-only", "--no-rebase", "--no-recurse-submodules"); err != nil {
			return "", "", err
		}
	}
	resolved := ref
	target := "HEAD"
	if ref == "" {
		branch, err := c.git(ctx, checkout, "symbolic-ref", "--short", "HEAD")
		if err != nil {
			return "", "", err
		}
		resolved = strings.TrimSpace(string(branch))
	} else {
		// Fetch the exact requested branch, tag, or SHA without switching the
		// default branch checkout; later pulls keep their normal upstream.
		if _, err = c.git(ctx, checkout, "fetch", "--no-recurse-submodules", "origin", ref); err != nil {
			return "", "", err
		}
		target = "FETCH_HEAD"
	}
	out, err := c.git(ctx, checkout, "rev-parse", "--verify", target+"^{commit}")
	if err != nil {
		return "", "", err
	}
	sha := strings.TrimSpace(string(out))
	if !commitPattern.MatchString(sha) {
		return "", "", fmt.Errorf("Git did not return a full commit SHA")
	}
	dest := filepath.Join(root, sha+".tar.gz")
	meta := dest + ".json"
	if _, err := os.Lstat(meta); os.IsNotExist(err) {
		tmp, err := os.CreateTemp(root, "archive-*.part")
		if err != nil {
			return "", "", err
		}
		tmp.Close()
		defer os.Remove(tmp.Name())
		if _, err = c.git(ctx, checkout, "archive", "--format=tar.gz", "--prefix=source/", "--output="+tmp.Name(), sha); err != nil {
			return "", "", err
		}
		info, err := os.Stat(tmp.Name())
		limit := c.MaxArchiveBytes
		if limit <= 0 {
			limit = defaultArchiveLimit
		}
		if err != nil || info.Size() > limit {
			return "", "", fmt.Errorf("Git source archive exceeds size limit or is unavailable")
		}
		digest, err := store.SHA256(tmp.Name())
		if err != nil {
			return "", "", err
		}
		if err = os.Rename(tmp.Name(), dest); err != nil {
			return "", "", err
		}
		if err = store.JSON(meta, cachedArchive{Repository: repo.URL(), Revision: sha, SHA256: digest, DownloadedAt: time.Now().UTC()}); err != nil {
			return "", "", err
		}
	}
	// Validation of existing archives is done by Acquire, including SHA-256.
	return sha, resolved, nil
}
