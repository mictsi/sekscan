package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitClonePullRefsAndOffline(t *testing.T) {
	ctx := context.Background()
	remote := t.TempDir()
	run := func(dir string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
		return out
	}
	run(remote, "init", "-b", "main")
	run(remote, "config", "user.name", "Test")
	run(remote, "config", "user.email", "test@example.test")
	commit := func(body string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(remote, "file.txt"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		run(remote, "add", ".")
		run(remote, "commit", "-m", body)
		return strings.TrimSpace(string(run(remote, "rev-parse", "HEAD")))
	}
	first := commit("first")
	run(remote, "tag", "v1")
	repo, _ := ParseRepository("org/repo")
	c := &Client{Cache: t.TempDir()}
	var commands []string
	var checkout string
	c.GitCommand = func(ctx context.Context, dir string, args ...string) ([]byte, error) {
		commands = append(commands, args[0])
		if args[0] == "clone" {
			args = append([]string{}, args...)
			args[len(args)-2] = remote
		}
		if args[0] == "remote" {
			return []byte(repo.URL() + ".git"), nil
		}
		if args[0] == "pull" {
			checkout = dir
		}
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		return cmd.Output()
	}
	acquire := func(ref, want string, offline bool) {
		t.Helper()
		s, err := c.Acquire(ctx, repo, ref, "", offline)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if s.Revision != want || !s.Complete {
			t.Fatalf("%+v", s)
		}
		if _, err := os.Stat(filepath.Join(s.Path, "file.txt")); err != nil {
			t.Fatal(err)
		}
	}
	acquire("", first, false)
	second := commit("second")
	acquire("", second, false)
	if strings.Join(commands, ",") == "" || checkout == "" {
		t.Fatal("missing pull")
	}
	clones := 0
	for _, v := range commands {
		if v == "clone" {
			clones++
		}
	}
	if clones != 1 {
		t.Fatal("cloned more than once", commands)
	}
	acquire("v1", first, false)
	acquire(first, first, false)
	n := len(commands)
	acquire(first, first, true)
	if len(commands) != n {
		t.Fatal("offline executed git")
	}
	if _, err := c.Acquire(ctx, repo, "main", "", true); err == nil {
		t.Fatal("offline mutable ref")
	}
	if _, err := c.Acquire(ctx, repo, first, "missing", true); err == nil {
		t.Fatal("missing subdir")
	}
	if err := os.WriteFile(filepath.Join(checkout, "file.txt"), []byte("local changes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Acquire(ctx, repo, "", "", false); err == nil || !strings.Contains(err.Error(), "local changes") {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(c.Cache, "sources", "github", "*", first+".tar.gz"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	os.WriteFile(files[0], []byte("corrupt"), 0600)
	if _, err := c.Acquire(ctx, repo, first, "", true); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatal(err)
	}
}

func TestGitFailureAndCancellation(t *testing.T) {
	c := &Client{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.git(ctx, "", "version"); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := c.git(context.Background(), "", "invalid-command-SECRET"); err == nil {
		t.Fatal("expected failure")
	}
	if ValidateRef("--upload-pack=bad") == nil {
		t.Fatal("option accepted")
	}
}
