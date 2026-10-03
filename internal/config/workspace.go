package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Selection captures discovery separately so CI can require a trusted explicit choice.
type Selection struct{ File, Root, Source string }

func Discover(explicit, home, executable string, disabled, ci bool) (Selection, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return Selection{}, err
	}
	root := cwd
	if home != "" {
		root, err = filepath.Abs(home)
		if err != nil {
			return Selection{}, err
		}
	}
	if disabled {
		if explicit != "" {
			return Selection{}, fmt.Errorf("--config and --no-config are mutually exclusive")
		}
		return Selection{Root: root, Source: "defaults"}, nil
	}
	chosen, source := explicit, "flag"
	if chosen == "" {
		chosen = os.Getenv("SEKSCAN_CONFIG")
		source = "environment"
	}
	if chosen != "" {
		chosen, err = filepath.Abs(chosen)
		if err != nil {
			return Selection{}, err
		}
		if home == "" {
			root = configRoot(chosen)
		}
		return Selection{File: chosen, Root: root, Source: source}, nil
	}
	candidates := []string{filepath.Join(root, "sekscan.json"), filepath.Join(root, "config", "sekscan.json")}
	if home == "" && executable != "" {
		base := filepath.Dir(executable)
		candidates = append(candidates, filepath.Join(base, "sekscan.json"), filepath.Join(base, "config", "sekscan.json"))
	}
	for _, p := range candidates {
		st, e := os.Stat(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return Selection{}, e
		}
		if !st.Mode().IsRegular() {
			return Selection{}, fmt.Errorf("configuration is not a regular file: %s", p)
		}
		if ci {
			return Selection{}, fmt.Errorf("CI refuses auto-discovered configuration; use --config with a trusted file, or --no-config")
		}
		if home == "" {
			root = configRoot(p)
		}
		return Selection{File: p, Root: root, Source: "discovered"}, nil
	}
	return Selection{Root: root, Source: "defaults"}, nil
}
func configRoot(p string) string {
	r := filepath.Dir(p)
	if filepath.Base(r) == "config" {
		r = filepath.Dir(r)
	}
	return r
}
func (c *Config) ResolvePaths(root string) {
	c.WorkspaceRoot, _ = filepath.Abs(root)
	for _, p := range []*string{&c.Paths.Bin, &c.Paths.Cache, &c.Paths.Logs, &c.Paths.Data, &c.Storage.Path} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(root, *p)
		}
	}
}
func (c Config) validateWorkspace() error {
	for _, p := range []string{c.Paths.Bin, c.Paths.Cache, c.Paths.Logs, c.Paths.Data} {
		if strings.TrimSpace(p) == "" || strings.ContainsRune(p, 0) {
			return fmt.Errorf("workspace paths must not be empty")
		}
	}
	if len(c.Project.Namespace) == 0 || len(c.Project.Namespace) > 128 || len(c.Project.Key) > 256 || len(c.Project.Name) > 256 {
		return fmt.Errorf("project namespace/key/name exceeds schema limits or namespace is empty")
	}
	switch c.Storage.Driver {
	case "sqlite", "postgres", "postgresql", "mssql", "sqlserver":
	default:
		return fmt.Errorf("storage.driver must be sqlite, postgres, or mssql")
	}
	if c.Storage.Driver == "sqlite" && c.Storage.Path == "" {
		return fmt.Errorf("sqlite storage needs a path")
	}
	if c.Storage.Driver != "sqlite" && c.Storage.AutoMigrate {
		return fmt.Errorf("remote storage requires auto_migrate=false; use storage migrate with an administrator identity")
	}
	if c.Storage.Enabled && c.Storage.Driver != "sqlite" && c.Storage.DSNEnv == "" {
		return fmt.Errorf("remote storage requires dsn_env; do not store credentials in config")
	}
	if c.Storage.DSNEnv != "" && !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(c.Storage.DSNEnv) {
		return fmt.Errorf("invalid storage.dsn_env")
	}
	if d, e := time.ParseDuration(c.Storage.Timeout); e != nil || d <= 0 {
		return fmt.Errorf("storage.timeout must be a positive duration")
	}
	if c.Storage.MaxOpenConns < 1 || c.Storage.MaxOpenConns > 64 {
		return fmt.Errorf("storage.max_open_conns must be 1..64")
	}
	if c.Storage.MaxArtifactMB < 1 || c.Storage.MaxArtifactMB > 256 {
		return fmt.Errorf("storage.max_artifact_mb must be 1..256")
	}
	return nil
}
func validateTool(name string, t Tool) error {
	for _, arg := range t.CommandArgs {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return fmt.Errorf("invalid command_args for %s", name)
		}
	}
	for _, arg := range t.ExtraArgs {
		key := strings.SplitN(arg, "=", 2)[0]
		switch key {
		case "--no-fail", "--failure-threshold", "--disable-ignore-pragma", "-f", "--file-path-in-report", "--sarif-output", "--json-output", "--autofix", "--fix", "-fmt", "-out", "-conf", "-config-file", "-format", "-shellcheck", "-pyflakes", "--", "--config", "-c", "--output", "-o", "--format", "--exit-code", "--scanners", "--report-path", "--report-format", "--redact", "--cache-dir":
			return fmt.Errorf("tool %s extra_args cannot override protected option %s", name, key)
		}
		if (strings.HasPrefix(arg, "-o") && !strings.HasPrefix(arg, "--")) || (strings.HasPrefix(arg, "-c") && !strings.HasPrefix(arg, "--")) {
			return fmt.Errorf("tool %s extra_args contains a protected short option", name)
		}
	}
	if t.Install == nil {
		return nil
	}
	i := t.Install
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`).MatchString(i.Repository) {
		return fmt.Errorf("tool %s install.repository must be owner/repo", name)
	}
	if len(i.Assets) == 0 || i.Checksums == "" {
		return fmt.Errorf("tool %s install requires assets and checksums", name)
	}
	for platform, a := range i.Assets {
		if !regexp.MustCompile(`^(linux|darwin|windows)/(amd64|arm64)$`).MatchString(platform) {
			return fmt.Errorf("invalid install platform %q", platform)
		}
		if e := validateAsset(a); e != nil {
			return e
		}
	}
	if e := validateAsset(i.Checksums); e != nil {
		return e
	}
	if i.Executable != "" && !safeName.MatchString(i.Executable) {
		return fmt.Errorf("invalid install executable basename")
	}
	return nil
}
func validateAsset(s string) error {
	if s == "" || strings.ContainsAny(s, "/\\\x00") || strings.Contains(s, "..") {
		return fmt.Errorf("release asset must be a safe basename")
	}
	rest := strings.NewReplacer("{version}", "", "{os}", "", "{arch}", "").Replace(s)
	if strings.ContainsAny(rest, "{}") {
		return fmt.Errorf("unknown install template placeholder")
	}
	return nil
}
