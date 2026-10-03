// moduleupdate updates and validates the production module graph on a connected
// development machine. It never replaces external scanner executable versions.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

type module struct {
	Path    string
	Version string
	Main    bool
	Update  *module
	Replace *module
	GoMod   string
}
type updater struct {
	ctx  context.Context
	root string
}

func (u updater) run(capture bool, args ...string) ([]byte, error) {
	slog.Info("go command", "args", strings.Join(args, " "))
	cmd := exec.CommandContext(u.ctx, "go", args...)
	cmd.Dir = u.root
	cmd.Stderr = os.Stderr
	if !capture {
		cmd.Stdout = os.Stdout
		return nil, cmd.Run()
	}
	return cmd.Output()
}
func modules(raw []byte) ([]module, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	out := []module{}
	for {
		var m module
		err := dec.Decode(&m)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
}
func requiredLibc(raw []byte) (string, error) {
	// Go modules use whitespace-delimited requirements; comments may follow.
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(strings.SplitN(line, "//", 2)[0])
		if len(f) > 0 && f[0] == "require" {
			f = f[1:]
		}
		if len(f) >= 2 && f[0] == "modernc.org/libc" && strings.HasPrefix(f[1], "v") {
			return f[1], nil
		}
	}
	return "", fmt.Errorf("SQLite's module file does not declare modernc.org/libc; manual review required")
}
func (u updater) alignSQLite() error {
	raw, err := u.run(true, "list", "-m", "-json", "modernc.org/sqlite")
	if err != nil {
		return err
	}
	var m module
	if err = json.Unmarshal(raw, &m); err != nil {
		return err
	}
	raw, err = u.run(true, "mod", "download", "-json", "modernc.org/sqlite@"+m.Version)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &m); err != nil {
		return err
	}
	b, err := os.ReadFile(m.GoMod)
	if err != nil {
		return err
	}
	v, err := requiredLibc(b)
	if err != nil {
		return err
	}
	slog.Info("preserving SQLite's tested libc pairing", "sqlite", m.Version, "libc", v)
	_, err = u.run(false, "get", "modernc.org/libc@"+v)
	return err
}
func update(ctx context.Context, root string) (err error) {
	// Backup survives an uncatchable process termination; normal errors roll back.
	backup, err := os.MkdirTemp(root, ".module-update-backup-")
	if err != nil {
		return err
	}
	existed := map[string]bool{}
	for _, name := range []string{"go.mod", "go.sum"} {
		b, e := os.ReadFile(filepath.Join(root, name))
		if os.IsNotExist(e) && name == "go.sum" {
			continue
		}
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(backup, name), b, 0600); e != nil {
			return e
		}
		existed[name] = true
	}
	committed := false
	defer func() {
		if !committed {
			var restoreErr error
			for _, name := range []string{"go.mod", "go.sum"} {
				if existed[name] {
					b, e := os.ReadFile(filepath.Join(backup, name))
					if e == nil {
						e = os.WriteFile(filepath.Join(root, name), b, 0644)
					}
					restoreErr = errors.Join(restoreErr, e)
				} else {
					e := os.Remove(filepath.Join(root, name))
					if !os.IsNotExist(e) {
						restoreErr = errors.Join(restoreErr, e)
					}
				}
			}
			if restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("restore failed; original module files remain in %s: %w", backup, restoreErr))
				return
			}
			slog.Warn("module files restored; update was not completed")
		}
		os.RemoveAll(backup)
	}()
	u := updater{ctx: ctx, root: root}
	if _, err = u.run(false, "version"); err != nil {
		return err
	}
	if _, err = u.run(false, "get", "-u", "-t", "./..."); err != nil {
		return err
	}
	var final []byte
	for pass := 0; pass < 5; pass++ {
		if err = u.alignSQLite(); err != nil {
			return err
		}
		if _, err = u.run(false, "mod", "tidy"); err != nil {
			return err
		}
		final, err = u.run(true, "list", "-m", "-u", "-json", "all")
		if err != nil {
			return err
		}
		list, e := modules(final)
		if e != nil {
			return e
		}
		args := []string{"get"}
		for _, m := range list {
			if m.Replace != nil {
				return fmt.Errorf("module replacements require manual review: %s", m.Path)
			}
			if m.Main || m.Update == nil {
				continue
			}
			if m.Path == "modernc.org/libc" {
				slog.Warn("newer libc intentionally not selected; SQLite requires its tested version", "version", m.Version, "available", m.Update.Version)
				continue
			}
			args = append(args, m.Path+"@latest")
		}
		if len(args) == 1 {
			break
		}
		if pass == 4 {
			return fmt.Errorf("module graph did not converge to latest versions; files rolled back")
		}
		if _, err = u.run(false, args...); err != nil {
			return err
		}
	}
	for _, args := range [][]string{{"mod", "verify"}, {"test", "./..."}, {"vet", "./..."}} {
		if _, err = u.run(false, args...); err != nil {
			return err
		}
	}
	result := filepath.Join(root, "module-updates.json")
	reportModules, parseErr := modules(final)
	if parseErr != nil {
		return parseErr
	}
	reportBytes, marshalErr := json.MarshalIndent(reportModules, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	if err = os.WriteFile(result, append(reportBytes, '\n'), 0644); err != nil {
		return err
	}
	committed = true
	slog.Info("module update validated; review and commit go.mod and go.sum", "report", result)
	return nil
}
func main() {
	yes := flag.Bool("yes", false, "approve updating module files and downloading dependencies")
	root := flag.String("root", ".", "source directory containing go.mod")
	timeout := flag.Duration("timeout", 30*time.Minute, "operation timeout")
	flag.Parse()
	if !*yes {
		slog.Error("requires --yes; run from a clean checkout")
		os.Exit(2)
	}
	absolute, err := filepath.Abs(*root)
	if err != nil {
		slog.Error("invalid root")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if err = update(ctx, absolute); err != nil {
		slog.Error("module update failed", "error", err)
		os.Exit(1)
	}
}
