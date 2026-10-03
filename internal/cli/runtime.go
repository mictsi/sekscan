package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sekscan/internal/config"
	"sekscan/internal/scan"
	"sekscan/internal/workspace"
	"strconv"
	"strings"
	"sync"
	"time"
)

type runtimeKey struct{}
type appRuntime struct {
	Config    config.Config
	Selection config.Selection
}

func option(args []string, name string) string {
	value := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			break
		}
		if args[i] == "--"+name && i+1 < len(args) {
			value = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--"+name+"=") {
			value = strings.TrimPrefix(args[i], "--"+name+"=")
		}
	}
	return value
}
func boolOption(args []string, name string) bool {
	value := false
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "--"+name {
			value = true
		}
		if strings.HasPrefix(a, "--"+name+"=") {
			value, _ = strconv.ParseBool(strings.TrimPrefix(a, "--"+name+"="))
		}
	}
	return value
}
func isCI() bool {
	for _, key := range []string{"CI", "GITHUB_ACTIONS", "TF_BUILD"} {
		v := strings.ToLower(os.Getenv(key))
		if v != "" && v != "false" && v != "0" {
			return true
		}
	}
	return false
}
func setupRuntime(args []string) (*appRuntime, error) {
	exe, _ := os.Executable()
	selection, e := config.Discover(option(args, "config"), option(args, "home"), exe, boolOption(args, "no-config"), boolOption(args, "ci") || isCI())
	if e != nil {
		return nil, e
	}
	c, e := config.Load(selection.File)
	if e != nil {
		return nil, e
	}
	if boolOption(args, "diagnostic-stderr") {
		c.DiagnosticStderr = true
	}
	c.ResolvePaths(selection.Root)
	for _, v := range []struct {
		flag string
		dest *string
	}{{"tools-dir", &c.Paths.Bin}, {"cache-dir", &c.Paths.Cache}, {"logs-dir", &c.Paths.Logs}} {
		if p := option(args, v.flag); p != "" {
			*v.dest, e = filepath.Abs(p)
			if e != nil {
				return nil, e
			}
		}
	}
	if e = c.ValidatePortable(); e != nil {
		return nil, e
	}
	if e = workspace.Ensure(c); e != nil {
		return nil, e
	}
	return &appRuntime{Config: c, Selection: selection}, nil
}
func loadCommon(ctx context.Context, c *common) (config.Config, error) {
	if rt, ok := ctx.Value(runtimeKey{}).(*appRuntime); ok {
		c.config = rt.Selection.File
		c.tools = rt.Config.Paths.Bin
		c.cache = rt.Config.Paths.Cache
		return rt.Config, nil
	}
	return config.Load(c.config)
}
func runtimeOptions(ctx context.Context) []string {
	rt, ok := ctx.Value(runtimeKey{}).(*appRuntime)
	if !ok {
		return []string{"--no-config"}
	}
	out := []string{"--home", rt.Selection.Root, "--tools-dir", rt.Config.Paths.Bin, "--cache-dir", rt.Config.Paths.Cache}
	if rt.Selection.File != "" {
		out = append(out, "--config", rt.Selection.File)
	} else {
		out = append(out, "--no-config")
	}
	return out
}

// Each invocation owns its log file. Rotation avoids concurrent-process rename races.
type sessionLog struct {
	mu         sync.Mutex
	root, base string
	file       *os.File
	size       int
	part       int
}

func newSessionLog(dir string) (*sessionLog, error) {
	f, e := os.CreateTemp(dir, "sekscan-"+time.Now().UTC().Format("20060102T150405")+"-*.jsonl")
	if e != nil {
		return nil, e
	}
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return nil, e
	}
	return &sessionLog{root: dir, base: strings.TrimSuffix(filepath.Base(f.Name()), ".jsonl"), file: f}, nil
}
func (w *sessionLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+len(p) > 10<<20 {
		if e := w.file.Close(); e != nil {
			return 0, e
		}
		w.part++
		f, e := os.OpenFile(filepath.Join(w.root, fmt.Sprintf("%s-part%d.jsonl", w.base, w.part)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return 0, e
		}
		w.file = f
		w.size = 0
	}
	n, e := w.file.Write(p)
	w.size += n
	return n, e
}
func (w *sessionLog) Close() error { w.mu.Lock(); defer w.mu.Unlock(); return w.file.Close() }

type diagnosticWriter struct {
	out io.Writer
	log *slog.Logger
}

func (w diagnosticWriter) Write(p []byte) (int, error) {
	w.log.Info("diagnostic", "message", strings.TrimSpace(string(p)))
	return w.out.Write(p)
}

func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	// Keep project validation and named commands unchanged. Never change cwd
	// or discover executable configuration inside an untrusted scan target.
	if len(args) > 0 && strings.HasPrefix(args[0], "github:") {
		args = append([]string{"github", strings.TrimPrefix(args[0], "github:")}, args[1:]...)
	}
	if len(args) > 0 && scan.HasTargetPrefix(args[0]) {
		args = append([]string{"scan"}, args...)
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "version" || args[0] == "--version" || args[0] == "--help" || args[0] == "-h" {
		return runCommand(ctx, args, out, errOut)
	}
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "--help" || a == "-h" {
			return runCommand(ctx, args, out, errOut)
		}
	}
	// Planning/schema operations must work before a workspace exists and must not
	// trust or create application configuration, logs, caches or databases.
	if (args[0] == "batch" && len(args) > 1 && (args[1] == "schema" || args[1] == "validate")) ||
		((args[0] == "batch" || args[0] == "github") && boolOption(args, "dry-run")) {
		return runCommand(ctx, args, out, errOut)
	}
	rt, e := setupRuntime(args)
	if e != nil {
		fmt.Fprintln(errOut, "sekscan:", e)
		return 2
	}
	sink, e := newSessionLog(rt.Config.Paths.Logs)
	if e != nil {
		fmt.Fprintln(errOut, "sekscan: cannot create application log")
		return 2
	}
	defer sink.Close()
	log := slog.New(slog.NewJSONHandler(sink, nil))
	log.Info("command_started", "command", args[0], "config_source", rt.Selection.Source)
	for _, warning := range rt.Config.MigrationWarnings {
		log.Warn("configuration_migration", "message", warning)
		fmt.Fprintln(errOut, "sekscan: warning:", warning)
	}
	ctx = context.WithValue(ctx, runtimeKey{}, rt)
	code := runCommand(ctx, args, out, diagnosticWriter{out: errOut, log: log})
	log.Info("command_finished", "command", args[0], "exit_code", code)
	return code
}
