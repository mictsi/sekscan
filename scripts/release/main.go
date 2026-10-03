// release builds production sekscan ZIPs. This module has no external dependencies.
package main

import (
	"bytes"
	"context"
	_ "embed"
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
	"regexp"
	"runtime"
	"strings"
	"time"
)

//go:embed targets.json
var targetManifest []byte

// This same manifest is read by scripts/release_event.py before publishing.
var supportedTargets = loadTargetManifest()

func loadTargetManifest() []string {
	var targets []string
	if err := json.Unmarshal(targetManifest, &targets); err != nil || len(targets) == 0 {
		panic("invalid embedded release target manifest")
	}
	seen := map[string]bool{}
	for _, target := range targets {
		if !regexp.MustCompile(`^(linux|darwin|windows)/(amd64|arm64)$`).MatchString(target) || seen[target] {
			panic("unsafe or duplicate embedded release target")
		}
		seen[target] = true
	}
	return targets
}

var versionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$`)
var sourceVersion = regexp.MustCompile(`(?m)^var Version = "([^"]+)"`)

type options struct {
	Root, Out, Version string
	Targets            []string
	SkipTests, Source  bool
	Timestamp          time.Time
}

type builder struct {
	opts options
	ctx  context.Context
	log  *slog.Logger
	out  io.Writer
}

type artifact struct {
	File   string `json:"file"`
	Target string `json:"target,omitempty"`
	SHA256 string `json:"sha256"`
}

type manifest struct {
	Schema           int        `json:"schema_version"`
	Application      string     `json:"application"`
	Version          string     `json:"version"`
	Created          string     `json:"created_utc"`
	GoVersion        string     `json:"go_version"`
	GoModSHA256      string     `json:"go_mod_sha256"`
	GoSumSHA256      string     `json:"go_sum_sha256"`
	Targets          []string   `json:"targets"`
	HostTests        string     `json:"host_tests"`
	NativeSmoke      []string   `json:"native_version_smoke_targets"`
	BinariesSigned   bool       `json:"publisher_signed"`
	ToolsBundled     bool       `json:"scanner_tools_bundled"`
	DatabasesBundled bool       `json:"scanner_databases_bundled"`
	Artifacts        []artifact `json:"artifacts"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	f := flag.NewFlagSet("build-release", flag.ContinueOnError)
	f.SetOutput(errOut)
	root := f.String("root", "../..", "source directory (wrappers set this automatically)")
	version := f.String("version", os.Getenv("VERSION"), "release version; default: internal/cli/cli.go")
	targets := f.String("targets", "all", "all, or a comma-separated subset of supported GOOS/GOARCH pairs")
	destination := f.String("out", "", "new output directory; default: <source>/dist/<version>")
	skip := f.Bool("skip-tests", false, "skip host tests and vet (recorded as skipped in release manifest)")
	source := f.Bool("source", true, "also create a source ZIP from approved source/documentation paths")
	list := f.Bool("list-targets", false, "print supported release targets and exit")
	f.Usage = func() {
		fmt.Fprintln(errOut, "Build production sekscan releases: one ZIP per target, docs, configs, source ZIP, and SHA256SUMS.txt.")
		fmt.Fprintln(errOut, "Usage: build-release [--version 0.6.4-preview] [--targets all] [--out DIRECTORY]")
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(f.Args(), " "))
	}
	if *list {
		_, err := fmt.Fprintln(out, strings.Join(supportedTargets, "\n"))
		return err
	}
	resolved, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	resolved, err = filepath.EvalSymlinks(resolved)
	if err != nil {
		return fmt.Errorf("source directory: %w", err)
	}
	o := options{Root: resolved, Version: *version, Out: *destination, SkipTests: *skip, Source: *source}
	if o.Version == "" {
		raw, err := os.ReadFile(filepath.Join(o.Root, "internal/cli/cli.go"))
		if err != nil {
			return fmt.Errorf("read default version: %w", err)
		}
		match := sourceVersion.FindSubmatch(raw)
		if len(match) != 2 {
			return fmt.Errorf("cannot determine version; supply --version")
		}
		o.Version = string(match[1])
	}
	if !versionPattern.MatchString(o.Version) {
		return fmt.Errorf("invalid version %q; use a version such as 0.4.0-preview", o.Version)
	}
	o.Version = strings.TrimPrefix(o.Version, "v")
	if o.Targets, err = parseTargets(*targets); err != nil {
		return err
	}
	if o.Out == "" {
		o.Out = filepath.Join(o.Root, "dist", o.Version)
	} else {
		if !filepath.IsAbs(o.Out) {
			o.Out = filepath.Join(o.Root, o.Out)
		}
		o.Out = filepath.Clean(o.Out)
	}
	if o.Timestamp, err = buildTime(os.Getenv("SOURCE_DATE_EPOCH")); err != nil {
		return err
	}
	if err := preflight(o); err != nil {
		return err
	}
	logDir := filepath.Join(o.Root, "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return fmt.Errorf("create build logs: %w", err)
	}
	logFile, err := os.CreateTemp(logDir, "build-release-"+o.Version+"-*.log")
	if err != nil {
		return err
	}
	defer logFile.Close()
	writer := io.MultiWriter(out, logFile)
	log := slog.New(slog.NewTextHandler(writer, nil))
	log.Info("release started", "version", o.Version, "targets", strings.Join(o.Targets, ","), "log", logFile.Name())
	b := builder{opts: o, ctx: ctx, log: log, out: writer}
	if err := b.build(); err != nil {
		log.Error("release failed; no release directory published", "error", err)
		return err
	}
	log.Info("release complete", "directory", o.Out, "publisher_signed", false, "tools_bundled", false)
	return nil
}

func parseTargets(value string) ([]string, error) {
	if value == "all" {
		return append([]string(nil), supportedTargets...), nil
	}
	allowed := make(map[string]bool)
	for _, t := range supportedTargets {
		allowed[t] = true
	}
	seen := make(map[string]bool)
	var result []string
	for _, part := range strings.Split(value, ",") {
		t := strings.TrimSpace(part)
		if !allowed[t] {
			return nil, fmt.Errorf("unsupported target %q; supported: %s", t, strings.Join(supportedTargets, ", "))
		}
		if seen[t] {
			return nil, fmt.Errorf("duplicate target %q", t)
		}
		seen[t] = true
		result = append(result, t)
	}
	return result, nil
}

func preflight(o options) error {
	// Staging under a packaged source directory would recursively package itself.
	for _, dir := range []string{"cmd", "internal", "docs", "examples", "schema", "scripts", "testdata", ".github", "third_party"} {
		base := filepath.Join(o.Root, dir)
		rel, err := filepath.Rel(base, o.Out)
		if err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))) {
			return fmt.Errorf("output must not be inside packaged input directory %s; use dist/ or an external directory", dir)
		}
	}
	if _, err := os.Lstat(o.Out); err == nil {
		return fmt.Errorf("output already exists: %s; choose another --out directory (existing releases are never overwritten)", o.Out)
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, name := range []string{"go.mod", "go.sum", "README.md", "TESTING.md", "CHANGELOG.md", "examples/workspace-sekscan.json", "scripts/release/README.md.tmpl"} {
		info, err := os.Lstat(filepath.Join(o.Root, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			if name == "go.sum" {
				return fmt.Errorf("a resolved, nonempty go.sum is required; run go mod tidy on a connected machine, review and commit go.mod/go.sum, then retry")
			}
			return fmt.Errorf("required regular, nonempty release input missing or unsafe: %s", name)
		}
	}
	for _, name := range []string{"cmd", "internal", "docs", "examples", "schema", "scripts", "internal/workspace/defaults", "third_party"} {
		info, err := os.Lstat(filepath.Join(o.Root, filepath.FromSlash(name)))
		if err != nil || !info.IsDir() {
			return fmt.Errorf("required release directory missing or unsafe: %s", name)
		}
	}
	return nil
}

func (b *builder) goCommand(dir, target string, capture bool, args ...string) ([]byte, error) {
	b.log.Info("running Go command", "directory", dir, "target", target, "args", strings.Join(args, " "))
	cmd := exec.CommandContext(b.ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = buildEnv(os.Environ(), target)
	cmd.Stderr = b.out
	cmd.WaitDelay = 5 * time.Second
	var buf bytes.Buffer
	if capture {
		cmd.Stdout = &buf
	} else {
		cmd.Stdout = b.out
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return buf.Bytes(), nil
}

func (b *builder) build() error {
	o := b.opts
	mod, err := hashFile(filepath.Join(o.Root, "go.mod"))
	if err != nil {
		return err
	}
	sum, err := hashFile(filepath.Join(o.Root, "go.sum"))
	if err != nil {
		return err
	}
	host := runtime.GOOS + "/" + runtime.GOARCH
	goVersion, err := b.goCommand(o.Root, host, true, "version")
	if err != nil {
		return err
	}
	b.log.Info("compiler", "version", strings.TrimSpace(string(goVersion)))
	if _, err := b.goCommand(o.Root, host, false, "mod", "verify"); err != nil {
		return err
	}
	moduleJSON, err := b.goCommand(o.Root, host, true, "list", "-mod=readonly", "-m", "-json", "all")
	if err != nil {
		return err
	}
	modules, err := parseModules(moduleJSON)
	if err != nil {
		return err
	}
	if !o.SkipTests {
		for _, dir := range []string{o.Root, filepath.Join(o.Root, "scripts", "release")} {
			for _, args := range [][]string{{"test", "-mod=readonly", "-count=1", "./..."}, {"vet", "-mod=readonly", "./..."}} {
				if _, err := b.goCommand(dir, host, false, args...); err != nil {
					return err
				}
			}
		}
	} else {
		b.log.Warn("host tests and vet explicitly skipped")
	}
	if err := modulesUnchanged(o.Root, mod, sum); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(o.Out), 0755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(o.Out), ".sekscan-release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	publish := filepath.Join(stage, "publish")
	if err := os.Mkdir(publish, 0755); err != nil {
		return err
	}
	m := manifest{Schema: 1, Application: "sekscan", Version: o.Version,
		Created: o.Timestamp.Format(time.RFC3339), GoVersion: strings.TrimSpace(string(goVersion)),
		GoModSHA256: mod, GoSumSHA256: sum, Targets: o.Targets, HostTests: "passed", NativeSmoke: []string{}}
	if o.SkipTests {
		m.HostTests = "skipped"
	}
	for _, target := range o.Targets {
		if err := b.ctx.Err(); err != nil {
			return err
		}
		parts := strings.Split(target, "/")
		name := "sekscan-" + o.Version + "-" + parts[0] + "-" + parts[1]
		payload := filepath.Join(stage, name)
		if err := os.Mkdir(payload, 0755); err != nil {
			return err
		}
		exe := "sekscan"
		if parts[0] == "windows" {
			exe += ".exe"
		}
		binary := filepath.Join(payload, exe)
		args := []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -X sekscan/internal/cli.Version=" + o.Version, "-o", binary, "./cmd/sekscan"}
		if _, err := b.goCommand(o.Root, target, false, args...); err != nil {
			return err
		}
		if err := verifyBinary(binary, target); err != nil {
			return err
		}
		if err := os.Chmod(binary, 0755); err != nil {
			return err
		}
		if target == host {
			cmd := exec.CommandContext(b.ctx, binary, "version")
			cmd.Dir = payload
			cmd.Env = buildEnv(os.Environ(), host)
			cmd.Stderr = b.out
			cmd.WaitDelay = 5 * time.Second
			version, err := cmd.Output()
			if err != nil || !strings.Contains(string(version), "sekscan "+o.Version) || strings.Contains(string(version), "TEST-ONLY") {
				return fmt.Errorf("native version smoke check failed for %s: %v", target, err)
			}
			m.NativeSmoke = append(m.NativeSmoke, target)
		}
		if err := populatePayload(o, payload, target, modules); err != nil {
			return err
		}
		if err := writeChecksums(payload, "SHA256SUMS.txt"); err != nil {
			return err
		}
		zipName := name + ".zip"
		if err := zipTree(payload, filepath.Join(publish, zipName), o.Timestamp); err != nil {
			return err
		}
		digest, err := hashFile(filepath.Join(publish, zipName))
		if err != nil {
			return err
		}
		m.Artifacts = append(m.Artifacts, artifact{File: zipName, Target: target, SHA256: digest})
		if err := os.RemoveAll(payload); err != nil {
			return err
		}
		b.log.Info("target packaged", "target", target, "archive", zipName)
	}
	if o.Source {
		name := "sekscan-" + o.Version + "-source"
		payload := filepath.Join(stage, name)
		if err := populateSource(o.Root, payload); err != nil {
			return err
		}
		if err := writeChecksums(payload, "SHA256SUMS.txt"); err != nil {
			return err
		}
		if err := zipTree(payload, filepath.Join(publish, name+".zip"), o.Timestamp); err != nil {
			return err
		}
		digest, err := hashFile(filepath.Join(publish, name+".zip"))
		if err != nil {
			return err
		}
		m.Artifacts = append(m.Artifacts, artifact{File: name + ".zip", SHA256: digest})
	}
	if err := modulesUnchanged(o.Root, mod, sum); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(publish, "release.json"), m); err != nil {
		return err
	}
	if err := writeChecksums(publish, "SHA256SUMS.txt"); err != nil {
		return err
	}
	// Publish only after every requested target and every archive has succeeded.
	if _, err := os.Lstat(o.Out); err == nil {
		return fmt.Errorf("output appeared during build; refusing to overwrite %s", o.Out)
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(publish, o.Out)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}
