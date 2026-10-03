// Package cli implements the local and CI command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/dbstore"

	"sekscan/internal/deps"
	"sekscan/internal/model"
	"sekscan/internal/report"
	"sekscan/internal/runner"
	"sekscan/internal/scan"
	"sekscan/internal/scannerdb"
	"sekscan/internal/server"
	"sekscan/internal/store"
)

var Version = "0.6.5-preview"

const help = `sekscan — local-first application and container security

Usage:
  sekscan scan [target] --project NAME [options]
  sekscan <typed-target> --project NAME [options]  e.g. dir:/path/to/app
  sekscan batch FILE.json [--dry-run] [options]
  sekscan batch validate FILE.json | batch schema
  sekscan github OWNER/REPO [--ref REF] [--project NAME] [options]
  sekscan serve [report-directory] [--listen 127.0.0.1:8080]
  sekscan report <results.json> [--out directory]
  sekscan doctor [--all] [--json]
  sekscan deps status|check|install|update|lock|import [tool@version ...] [options]
  sekscan db update|status|export|import [options]
  sekscan config init|validate|show|enable-default-scanners|remove-semgrep [options]
  sekscan init [--home directory]
  sekscan prepare [--all] --yes [--update-tools] [--with-java]
  sekscan storage migrate|status|schema|import|backup [options]
  sekscan history portfolio|projects|list|trends|compare|export [options]
  sekscan serve [--project NAME] [options]  default: portfolio/history
  sekscan version

Targets:
  dir:.                       source/dependency directory (default)
  rootfs:./rootfs              unpacked image filesystem
  image:registry/app:tag       container image; digest references preferred
  docker-archive:./image.tar   docker save archive
  oci-archive:./image.tar      OCI archive
  oci-layout:./image-layout    OCI layout (engine support may vary)
  sbom:./sbom.json             inventory + Grype + license policy only

Start:
  sekscan init
  sekscan prepare --yes
  sekscan scan dir:. --project my-service --out security-report
  sekscan serve

Common options (after the command):
  --config FILE       explicit, trusted JSON configuration (local discovery is otherwise enabled)
  --tools-dir DIR     managed scanner installation directory
  --cache-dir DIR     scanner databases/cache directory
  --home DIR          workspace root for bin/, cache/, logs/, and data/
  --logs-dir DIR      application JSONL log directory
  --no-config         disable local and environment-based config discovery
  --ci                require an explicit trusted config when one is present
  --log-json          structured JSON logs on stderr (file logs are always JSONL)

Run any command with --help for its options.
Exit codes: 0=policy passed, 1=policy failed, 2=error or incomplete scan.
`

type common struct {
	config, tools, cache, home, logs string
	noConfig, ci                     bool
	logJSON                          bool
	diagnostic                       bool
}

func addCommon(f *flag.FlagSet) *common {
	c := &common{}
	f.StringVar(&c.config, "config", "", "trusted JSON configuration file")
	f.StringVar(&c.tools, "tools-dir", "", "managed scanner installation directory")
	f.StringVar(&c.cache, "cache-dir", "", "scanner cache directory")
	f.StringVar(&c.home, "home", "", "workspace root (defaults to config location or working directory)")
	f.StringVar(&c.logs, "logs-dir", "", "application logs directory")
	f.BoolVar(&c.noConfig, "no-config", false, "disable configuration discovery")
	f.BoolVar(&c.ci, "ci", false, "require an explicitly trusted configuration when one is discovered")
	f.BoolVar(&c.diagnostic, "diagnostic-stderr", false, "save failed probes, scanner stderr and selected processing errors privately under logs; may contain secrets")
	f.BoolVar(&c.logJSON, "log-json", false, "write structured JSON logs to stderr")
	return c
}
func logger(c *common, out io.Writer) *slog.Logger {
	if c.logJSON {
		return slog.New(slog.NewJSONHandler(out, nil))
	}
	return slog.New(slog.NewTextHandler(out, nil))
}
func set(name string, err io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(err)
	return f
}

// Parse interspersed flags while keeping values as literal argv elements.
func parse(f *flag.FlagSet, args []string) error {
	flags, positionals := []string{}, []string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positionals = append(positionals, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-")
		v := f.Lookup(name)
		if v == nil {
			continue
		}
		if strings.Contains(a, "=") {
			continue
		}
		isBool := false
		if b, ok := v.Value.(interface{ IsBoolFlag() bool }); ok {
			isBool = b.IsBoolFlag()
		}
		if !isBool && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return f.Parse(append(append(flags, "--"), positionals...))
}
func runCommand(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(out, help)
		return 0
	}
	var code int
	var err error
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(out, "sekscan", Version, "["+dbstore.DriverBuild+"]")
		return 0
	case "scan":
		code, err = scanCommand(ctx, args[1:], out, errOut)
	case "batch":
		code, err = batchCommand(ctx, args[1:], out, errOut)
	case "github":
		code, err = githubCommand(ctx, args[1:], out, errOut)
	case "serve":
		err = serveCommand(ctx, args[1:], out, errOut)
	case "report":
		err = reportCommand(args[1:], out, errOut)
	case "doctor":
		err = depsCommand(ctx, append([]string{"status"}, args[1:]...), out, errOut)
	case "deps":
		err = depsCommand(ctx, args[1:], out, errOut)
	case "config":
		err = configCommand(ctx, args[1:], out, errOut)
	case "db":
		err = dbCommand(ctx, args[1:], out, errOut)
	case "init":
		err = initCommand(ctx, args[1:], out, errOut)
	case "prepare":
		err = prepareCommand(ctx, args[1:], out, errOut)
	case "storage":
		err = storageCommand(ctx, args[1:], out, errOut)
	case "history":
		err = historyCommand(ctx, args[1:], out, errOut)
	default:
		err = fmt.Errorf("unknown command %q; run sekscan --help", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(errOut, "sekscan:", err)
		return 2
	}
	return code
}
func scanCommand(ctx context.Context, args []string, out, errOut io.Writer) (int, error) {
	f := set("scan", errOut)
	common := addCommon(f)
	dest := f.String("out", "security-report", "report output directory")
	install := f.Bool("install-missing", false, "install missing managed prerequisites (requires --yes)")
	yes := f.Bool("yes", false, "approve prerequisite downloads")
	offline := f.Bool("offline", false, "disable supported engine network updates/enrichment")
	baselineFile := f.String("baseline", "", "prior results.json")
	failAt := f.String("fail-at", "", "override severity gate: critical/high/medium/low/info/none")
	onlyNew := f.Bool("only-new", false, "gate only findings absent from the baseline")
	noFailReview := f.Bool("allow-review", false, "do not fail solely on license/unknown-evidence review items")
	inventoryOnly := f.Bool("inventory-only", false, "only generate inventory and SBOMs; skip security checks")
	extraChecks := map[string]*bool{}
	for _, name := range []string{"hadolint", "zizmor", "govulncheck", "gosec"} {
		extraChecks[name] = f.Bool(name, false, "override this default check; use =false to disable")
	}
	withGitleaks := f.Bool("gitleaks", false, "override default Gitleaks scan; use =false to disable")
	withActionlint := f.Bool("actionlint", false, "override default actionlint scan; use =false to disable")
	withTrivyVuln := f.Bool("trivy-vuln", false, "also scan vulnerabilities with Trivy")
	revision := f.String("revision", "", "source commit or build revision to record")
	project := f.String("project", "", "required project name/key; may also be set in project.key configuration")
	branch := f.String("branch", "", "branch metadata for history")
	noStore := f.Bool("no-store", false, "disable persistence for this scan")
	if e := parse(f, args); e != nil {
		return 0, e
	}
	if f.NArg() > 1 {
		return 0, fmt.Errorf("scan accepts one target")
	}
	c, e := loadCommon(ctx, common)
	if e != nil {
		return 0, e
	}
	if *project != "" {
		c.Project.Key = *project
	}
	if *noStore {
		c.Storage.Enabled = false
	}
	if e := config.RequireProject(c.Project); e != nil {
		return 0, e
	}
	if *failAt != "" {
		c.Policy.FailAt = *failAt
	}
	if *onlyNew {
		c.Policy.OnlyNew = true
	}
	if *noFailReview {
		c.Policy.FailOnReview = false
	}
	if common.diagnostic {
		c.DiagnosticStderr = true
	}
	visited := map[string]bool{}
	f.Visit(func(flag *flag.Flag) { visited[flag.Name] = true })
	if visited["actionlint"] {
		c.Checks.Actionlint = *withActionlint
	}
	if visited["gitleaks"] {
		c.Checks.Gitleaks = *withGitleaks
	}
	if visited["trivy-vuln"] {
		c.Checks.TrivyVulnerabilities = *withTrivyVuln
	}
	if visited["hadolint"] {
		c.Checks.Hadolint = *extraChecks["hadolint"]
	}
	if visited["zizmor"] {
		c.Checks.Zizmor = *extraChecks["zizmor"]
	}
	if visited["govulncheck"] {
		c.Checks.Govulncheck = *extraChecks["govulncheck"]
	}
	if visited["gosec"] {
		c.Checks.Gosec = *extraChecks["gosec"]
	}
	if *inventoryOnly {
		c.Checks = config.Checks{}
		c.Extensions = nil
	}
	if e = c.Validate(); e != nil {
		return 0, e
	}
	targetText := "dir:."
	if f.NArg() == 1 {
		targetText = f.Arg(0)
	}
	target, e := scan.ParseTarget(targetText)
	if e != nil {
		return 0, fmt.Errorf("resolve scan target: %w", e)
	}
	if *install && !*yes {
		return 0, fmt.Errorf("--install-missing requires --yes")
	}
	if *install && *offline {
		return 0, fmt.Errorf("cannot install prerequisites in offline mode")
	}
	d := deps.NewConfigured(common.tools, c)
	if meta, ok := ctx.Value(scanMetadataKey{}).(scanMetadata); ok {
		d.DenyEnv = append(d.DenyEnv, meta.DenyEnv...)
	}
	log := logger(common, errOut)
	log.Info("scan target resolved", "kind", target.Kind, "target", target.Value, "project", c.Project.Key)
	if *install {
		names, err := scan.ToolsForTarget(ctx, c, target)
		if err != nil {
			return 0, err
		}
		for _, name := range names {
			if *inventoryOnly && name != "syft" {
				continue
			}
			status := d.Inspect(ctx, name, c.Tools[name])
			if status.Error != "" {
				log.Info("installing prerequisite", "tool", name)
				if _, e = d.Install(ctx, name, c.Tools[name]); e != nil {
					return 0, e
				}
			}
		}
	}
	var baseline *model.Report
	if *baselineFile != "" {
		baseline, e = report.Load(*baselineFile)
		if e != nil {
			return 0, e
		}
		if baseline.ProjectKey != c.Project.Key || baseline.Namespace != c.Project.Namespace {
			return 0, fmt.Errorf("baseline must have the same explicit project and namespace; import legacy reports with storage import --project first")
		}
	}
	output, e := filepath.Abs(*dest)
	if e != nil {
		return 0, e
	}
	if target.Kind == "dir" || target.Kind == "rootfs" || target.Kind == "oci-layout" {
		rel, err := filepath.Rel(output, target.Value)
		if err == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")) {
			return 0, fmt.Errorf("report directory must not equal or contain the scan target")
		}
	}
	cleanup, e := prepareOutput(output)
	if e != nil {
		return 0, e
	}
	defer cleanup()
	if *revision == "" {
		for _, key := range []string{"GITHUB_SHA", "BUILD_SOURCEVERSION"} {
			if v := os.Getenv(key); v != "" {
				*revision = v
				break
			}
		}
	}
	scanner := scan.Scanner{Config: c, Deps: d, Executor: runner.OSExecutor{}, Logger: log}
	options := scan.Options{Target: target, Output: output, Cache: common.cache, Offline: *offline, Baseline: baseline, Revision: *revision, AppVersion: Version}
	if meta, ok := ctx.Value(scanMetadataKey{}).(scanMetadata); ok {
		options.Source, options.BatchID = meta.Source, meta.BatchID
		options.SourceComplete, options.SourceWarnings = meta.Complete, meta.Warnings
		options.DenyEnv = meta.DenyEnv
	}
	if *inventoryOnly {
		// Inventory-only is explicit and does not imply a security assessment.
		r, err := scanner.Run(ctx, options)
		if err != nil {
			return 0, err
		}
		r.Warnings = append(r.Warnings, "Inventory-only mode: vulnerability, secret, configuration and supplemental license scans were intentionally disabled.")
		r.Branch = *branch
		r.ProjectKey, r.Namespace = c.Project.Key, c.Project.Namespace
		persistReport(ctx, c, r, output, log)
		if err = report.Write(output, r); err != nil {
			return 0, err
		}
		fmt.Fprintf(out, "%s: %d components; report %s\n", r.Status, len(r.Components), filepath.Join(output, "index.html"))
		return r.ExitCode, nil
	}
	r, e := scanner.Run(ctx, options)
	if e != nil {
		return 0, e
	}
	r.Branch = *branch
	r.ProjectKey, r.Namespace = c.Project.Key, c.Project.Namespace
	persistReport(ctx, c, r, output, log)
	if e = report.Write(output, r); e != nil {
		return 0, e
	}
	fmt.Fprintf(out, "%s: %d components, %d findings, %d failures, %d reviews\nReport: %s\n", strings.ToUpper(r.Status), r.Summary.Components, r.Summary.Findings, r.Summary.Failures, r.Summary.Reviews, filepath.Join(output, "index.html"))
	return r.ExitCode, nil
}
func prepareOutput(dir string) (func(), error) {
	if st, e := os.Lstat(dir); e == nil && st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("output directory must not be a symlink")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(filepath.Join(dir, ".sekscan.lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, fmt.Errorf("report directory is busy (remove .sekscan.lock only after confirming no scan is running): %w", e)
	}
	lock.Close()
	cleanup := func() { _ = os.Remove(filepath.Join(dir, ".sekscan.lock")) }
	marker := filepath.Join(dir, ".sekscan-report")
	entries, e := os.ReadDir(dir)
	if e != nil {
		cleanup()
		return nil, e
	}
	if len(entries) > 1 {
		if _, e = os.Stat(marker); e != nil {
			cleanup()
			return nil, fmt.Errorf("refusing to overwrite a nonempty directory not created by sekscan; choose a new --out directory")
		}
	}
	for _, name := range report.OutputFiles {
		if e = os.Remove(filepath.Join(dir, name)); e != nil && !os.IsNotExist(e) {
			cleanup()
			return nil, e
		}
	}
	if e = store.Atomic(marker, []byte("sekscan report directory\n"), 0600); e != nil {
		cleanup()
		return nil, e
	}
	return cleanup, nil
}
func serveCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	f := set("serve", errOut)
	common := addCommon(f)
	history := f.Bool("history", false, "browse database history (default when no report directory is supplied)")
	project := f.String("project", "", "filter database history to one project key")
	address := f.String("listen", "127.0.0.1:8080", "loopback host:port")
	if e := parse(f, args); e != nil {
		return e
	}
	if f.NArg() > 1 {
		return fmt.Errorf("serve accepts one report directory")
	}
	if f.NArg() == 0 {
		*history = true
	}
	if *project != "" {
		if !*history {
			return fmt.Errorf("serve --project cannot be combined with a report directory")
		}
		if e := config.RequireProject(config.Project{Key: *project}); e != nil {
			return e
		}
	}
	if *history {
		if f.NArg() != 0 {
			return fmt.Errorf("--history cannot be combined with a report directory")
		}
		c, e := loadCommon(ctx, common)
		if e != nil {
			return e
		}
		return serveHistory(ctx, c, *address, *project, out)
	}
	dir := "security-report"
	if f.NArg() == 1 {
		dir = f.Arg(0)
	}
	r, e := report.Load(filepath.Join(dir, "results.json"))
	if e != nil {
		return e
	}
	html, e := report.HTML(r)
	if e != nil {
		return e
	}
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	return server.Serve(ctx, *address, html, b, func(address string) { fmt.Fprintln(out, "Dashboard:", address, "(Ctrl+C to stop)") })
}
func reportCommand(args []string, out, errOut io.Writer) error {
	f := set("report", errOut)
	_ = addCommon(f)
	dest := f.String("out", "regenerated-report", "output directory")
	if e := parse(f, args); e != nil {
		return e
	}
	if f.NArg() != 1 {
		return fmt.Errorf("report requires a results.json file")
	}
	r, e := report.Load(f.Arg(0))
	if e != nil {
		return e
	}
	cleanup, e := prepareOutput(*dest)
	if e != nil {
		return e
	}
	defer cleanup()
	if e = report.Write(*dest, r); e != nil {
		return e
	}
	fmt.Fprintln(out, filepath.Join(*dest, "index.html"))
	return nil
}
func configCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("config requires init, show, validate, enable-default-scanners, or remove-semgrep")
	}
	f := set("config "+args[0], errOut)
	file := f.String("out", "sekscan.json", "file to create")
	common := addCommon(f)
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected config command arguments")
	}
	switch args[0] {
	case "init":
		if _, e := os.Stat(*file); e == nil {
			return fmt.Errorf("configuration already exists")
		}
		if e := store.JSON(*file, config.Default()); e != nil {
			return e
		}
		fmt.Fprintln(out, "Created", *file, "— discovered automatically for local commands")
		return nil
	case "remove-semgrep":
		c, err := loadCommon(ctx, common)
		if err != nil {
			return err
		}
		if _, err = os.Stat(*file); !os.IsNotExist(err) {
			return fmt.Errorf("choose a new --out file; existing configurations are never overwritten")
		}
		dir, err := filepath.Abs(filepath.Dir(*file))
		if err != nil {
			return err
		}
		if c.Portable && dir != c.WorkspaceRoot && dir != filepath.Join(c.WorkspaceRoot, "config") {
			return fmt.Errorf("save portable configuration in workspace root or config directory")
		}
		c = c.WithoutSemgrep()
		if err = c.Validate(); err != nil {
			return err
		}
		if err = store.JSON(*file, c.ForSave(dir)); err != nil {
			return err
		}
		fmt.Fprintln(out, "Created", *file, "without Semgrep; remaining checks, policy, storage and pins preserved")
		return nil
	case "enable-default-scanners":
		c, err := loadCommon(ctx, common)
		if err != nil {
			return err
		}
		if _, err = os.Stat(*file); !os.IsNotExist(err) {
			return fmt.Errorf("choose a new --out file; existing configurations are never overwritten")
		}
		dir, err := filepath.Abs(filepath.Dir(*file))
		if err != nil {
			return err
		}
		if c.Portable && dir != c.WorkspaceRoot && dir != filepath.Join(c.WorkspaceRoot, "config") {
			return fmt.Errorf("save upgraded portable configuration in workspace root or config directory")
		}
		c.Checks.Gitleaks = true
		c.Checks.Actionlint = true
		c.Checks.Hadolint = true
		c.Checks.Zizmor = true
		c.Checks.Govulncheck = true
		c.Checks.Gosec = true
		for name, file := range map[string]string{"hadolint": "hadolint.yaml", "gosec": "gosec.json"} {
			tool := c.Tools[name]
			if tool.NativeConfig == "" {
				tool.NativeConfig = filepath.Join(c.WorkspaceRoot, "config", file)
				c.Tools[name] = tool
			}
		}
		if err = c.Validate(); err != nil {
			return err
		}
		if err = store.JSON(*file, c.ForSave(dir)); err != nil {
			return err
		}
		fmt.Fprintln(out, "Created", *file, "with the default scanner suite; policy, paths, pins and explicit custom definitions preserved")
		return nil
	case "show":
		c, e := loadCommon(ctx, common)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(c)
	case "validate":
		if _, e := loadCommon(ctx, common); e != nil {
			return e
		}
		fmt.Fprintln(out, "Configuration is valid")
		return nil
	default:
		return fmt.Errorf("unknown config command")
	}
}
func depsCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("deps requires status, check, install, update, or lock")
	}
	action := args[0]
	if action == "import" {
		return importToolCommand(ctx, args[1:], out, errOut)
	}
	f := set("deps "+action, errOut)
	common := addCommon(f)
	all := f.Bool("all", false, "include all configured tools, including optional tools")
	yes := f.Bool("yes", false, "approve downloads from upstream GitHub releases")
	jsonOut := f.Bool("json", false, "print machine-readable JSON")
	output := f.String("out", "sekscan.lock.json", "configuration lock output file")
	version := f.String("version", "", "release version override (one tool only)")
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	c, e := loadCommon(ctx, common)
	if e != nil {
		return e
	}
	names := deps.ToolNames(c, *all)
	if f.NArg() > 0 {
		names = []string{}
		for _, spec := range f.Args() {
			name, v, hasVersion := strings.Cut(spec, "@")
			if config.RemovedScanner(name) {
				return fmt.Errorf("Semgrep support was removed in sekscan 0.6.5; it is no longer installed, tested, or scanned")
			}
			if _, ok := c.Tools[name]; !ok {
				return fmt.Errorf("unknown prerequisite %q", name)
			}
			if hasVersion {
				if !config.ValidVersion(v) {
					return fmt.Errorf("invalid tool version %q", v)
				}
				t := c.Tools[name]
				t.Version = v
				c.Tools[name] = t
			}
			names = append(names, name)
		}
	}
	if *version != "" {
		if len(names) != 1 || !config.ValidVersion(*version) {
			return fmt.Errorf("--version requires one tool and a valid version")
		}
		t := c.Tools[names[0]]
		t.Version = *version
		c.Tools[names[0]] = t
	}
	manager := deps.NewConfigured(common.tools, c)
	log := logger(common, errOut)
	switch action {
	case "check":
		updates := []deps.UpdateStatus{}
		failed := false
		for _, name := range names {
			u := manager.CheckUpdate(ctx, name, c.Tools[name])
			updates = append(updates, u)
			if u.State == "unknown" && u.Error != "" {
				failed = true
			}
			if !*jsonOut {
				fmt.Fprintf(out, "%-14s installed=%-12s latest=%-12s %s\n", name, u.Installed, u.Latest, u.State)
			}
		}
		if *jsonOut {
			if e = json.NewEncoder(out).Encode(updates); e != nil {
				return e
			}
		}
		if failed {
			return fmt.Errorf("one or more update checks failed")
		}
		return nil
	case "status", "lock":
		statuses := []deps.Status{}
		failed := false
		for _, name := range names {
			status := manager.Inspect(ctx, name, c.Tools[name])
			statuses = append(statuses, status)
			if status.Error != "" {
				failed = true
			}
			if action == "lock" && status.Error == "" {
				t := c.Tools[name]
				t.Version = status.Version
				c.Tools[name] = t
				if status.Source == "managed" {
					b, err := store.Read(filepath.Join(manager.Dir, name, "current.json"), 16<<20)
					if err == nil {
						var installed deps.Installed
						if json.Unmarshal(b, &installed) == nil {
							t.SHA256 = installed.ArchiveSHA256
							c.Tools[name] = t
						}
					}
				}
			}
		}
		if *jsonOut {
			if e = json.NewEncoder(out).Encode(statuses); e != nil {
				return e
			}
		} else {
			for _, s := range statuses {
				if s.Error != "" {
					fmt.Fprintf(out, "%-10s ERROR %s\n", s.Name, s.Error)
				} else {
					fmt.Fprintf(out, "%-10s %-14s %-10s %s\n", s.Name, s.Version, s.Source, s.Path)
				}
			}
		}
		if failed {
			return fmt.Errorf("one or more prerequisites are unavailable")
		}
		if action == "lock" {
			if c.Portable {
				dir, err := filepath.Abs(filepath.Dir(*output))
				if err != nil {
					return err
				}
				if dir != c.WorkspaceRoot && dir != filepath.Join(c.WorkspaceRoot, "config") {
					return fmt.Errorf("portable lockfiles must be saved in the workspace root or its config directory")
				}
			}
			if _, err := os.Stat(*output); err == nil {
				return fmt.Errorf("lock output already exists; choose another --out path")
			}
			if e = store.JSON(*output, c.ForSave(filepath.Dir(*output))); e != nil {
				return e
			}
			fmt.Fprintln(out, "Wrote", *output)
		}
		return nil
	case "install", "update":
		if !*yes {
			return fmt.Errorf("installation requires --yes; downloads execute upstream software, not an isolated sandbox")
		}
		installed := []deps.Installed{}
		errorsFound := []string{}
		for _, name := range names {
			log.Info("installing prerequisite", "tool", name, "version", c.Tools[name].Version)
			entry, err := manager.Install(ctx, name, c.Tools[name])
			if err != nil {
				errorsFound = append(errorsFound, name+": "+err.Error())
				continue
			}
			installed = append(installed, entry)
			if !*jsonOut {
				fmt.Fprintf(out, "Installed %s %s → %s\n", name, entry.Version, entry.Path)
			}
		}
		if *jsonOut {
			if e = json.NewEncoder(out).Encode(installed); e != nil {
				return e
			}
		}
		if len(errorsFound) > 0 {
			return fmt.Errorf("installation failures: %s", strings.Join(errorsFound, "; "))
		}
		return nil
	default:
		return fmt.Errorf("unknown deps action %q", action)
	}
}
func dbCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("db requires update, status, export or import")
	}
	action := args[0]
	f := set("db "+action, errOut)
	common := addCommon(f)
	output := f.String("out", "scanner-data.tar.gz", "bundle output path")
	input := f.String("file", "", "bundle input path")
	java := f.Bool("with-java", false, "include Trivy Java metadata database")
	all := f.Bool("all", false, "include databases for all configured tools")
	jsonOut := f.Bool("json", false, "output machine-readable database status")
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected database command arguments")
	}
	c, e := loadCommon(ctx, common)
	if e != nil {
		return e
	}
	cache, e := filepath.Abs(common.cache)
	if e != nil {
		return e
	}
	c.Paths.Cache = cache
	if action == "export" {
		return store.ExportBundle(cache, *output)
	}
	if action == "import" {
		if *input == "" {
			return fmt.Errorf("db import requires --file")
		}
		return store.ImportBundle(cache, *input)
	}
	manager := deps.NewConfigured(common.tools, c)
	show := func() error {
		statuses := scannerdb.Statuses(ctx, c, manager, *all, *java)
		failed := false
		for _, st := range statuses {
			if st.State != "ready" {
				failed = true
			}
			if !*jsonOut {
				fmt.Fprintf(out, "%-7s %-14s %-18s %s\n", st.Engine, st.Database, st.State, st.Path)
				if st.Error != "" {
					fmt.Fprintln(out, "  "+st.Error)
				}
			}
		}
		if *jsonOut {
			if e := json.NewEncoder(out).Encode(statuses); e != nil {
				return e
			}
		}
		if failed {
			return fmt.Errorf("one or more required scanner databases are not ready")
		}
		return nil
	}
	if action == "status" {
		return show()
	}
	if action != "update" {
		return fmt.Errorf("unknown db command")
	}
	temp, e := os.MkdirTemp("", "sekscan-db-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	empty := filepath.Join(temp, "empty.yaml")
	if e = store.Atomic(empty, []byte("{}\n"), 0600); e != nil {
		return e
	}
	warm := filepath.Join(temp, "checks-input")
	if e = os.MkdirAll(warm, 0700); e != nil {
		return e
	}
	// Force policy initialization using a controlled input, never the user's project.
	if e = store.Atomic(filepath.Join(warm, "Dockerfile"), []byte("FROM scratch\nUSER 65532\n"), 0600); e != nil {
		return e
	}
	type command struct {
		name, label string
		args        []string
	}
	commands := []command{
		{"grype", "vulnerability", []string{"--config", empty, "db", "update"}},
		{"trivy", "vulnerability", []string{"image", "--config", empty, "--cache-dir", filepath.Join(cache, "trivy"), "--download-db-only", "--no-progress"}},
	}
	if *java {
		commands = append(commands, command{"trivy", "java-index", []string{"image", "--config", empty, "--cache-dir", filepath.Join(cache, "trivy"), "--download-java-db-only", "--no-progress"}})
	}
	if c.Checks.Misconfigurations || *all {
		commands = append(commands, command{"trivy", "checks", []string{"filesystem", "--config", empty, "--cache-dir", filepath.Join(cache, "trivy"), "--scanners", "misconfig", "--format", "json", "--exit-code", "0", "--no-progress", "--", warm}})
	}
	env, e := manager.Environment(false)
	if e != nil {
		return e
	}
	log := logger(common, errOut)
	required := scannerdb.Selected(c, *all)
	if *java {
		required["trivy"] = true
	}
	failures := []string{}
	for _, command := range commands {
		if !required[command.name] {
			continue
		}
		native, err := scannerdb.NativeConfig(c, command.name, empty)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		for i, a := range command.args {
			if a == "--config" && i+1 < len(command.args) {
				command.args[i+1] = native
			}
		}
		status := manager.Inspect(ctx, command.name, c.Tools[command.name])
		if status.Error != "" {
			failures = append(failures, command.name+": "+status.Error)
			continue
		}
		log.Info("updating scanner data", "engine", command.name, "database", command.label, "cache", cache)
		result, err := manager.Executor.Run(ctx, runner.Request{Executable: status.Path, Args: manager.CommandArgs(command.name, c.Tools[command.name], command.args), Dir: temp, Env: env, Timeout: 20 * time.Minute, MaxOutput: 8 << 20})
		if c.DiagnosticStderr && len(result.Stderr) > 0 {
			name, saveErr := runner.SaveStderr(c.Paths.Logs, command.name+"-db", result.Stderr)
			if saveErr == nil {
				log.Warn("private database diagnostics saved; may contain secrets", "file", name)
			}
		}
		if err != nil {
			failures = append(failures, command.name+" "+command.label+": "+err.Error())
			continue
		}
		log.Info("scanner data update command completed", "engine", command.name, "database", command.label)
	}
	if required["govulncheck"] {
		log.Info("updating scanner data", "engine", "govulncheck", "cache", cache)
		if err := scannerdb.UpdateGovulncheck(ctx, c, manager.Client); err != nil {
			failures = append(failures, "govulncheck DB: "+err.Error())
		}
	}
	if err := show(); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("database preparation incomplete: %s", strings.Join(failures, "; "))
	}
	if !*jsonOut {
		fmt.Fprintln(out, "Selected scanner databases are prepared in", cache)
	}
	return nil
}
