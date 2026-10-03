package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FailureHint returns only fixed strings, never fragments of scanner output.
// A hint is a troubleshooting classification, not proof of the underlying cause.
func FailureHint(stderr []byte) string {
	if hint := GoFailureHint(stderr); hint != "" {
		return hint
	}
	text := strings.ToLower(string(stderr))
	switch {
	case (strings.Contains(text, "exclude") || strings.Contains(text, "exclusion")) && (strings.Contains(text, "relative") || strings.Contains(text, "glob") || strings.Contains(text, "pattern")):
		return "scanner rejected an exclusion path; check target-relative exclusions and scanner version"
	case strings.Contains(text, "unknown flag"), strings.Contains(text, "unknown shorthand flag"), strings.Contains(text, "flag provided but not defined"), strings.Contains(text, "unexpected argument"):
		return "scanner rejected an option; check native config, extra_args and CLI compatibility"
	case strings.Contains(text, "database") && (strings.Contains(text, "too old") || strings.Contains(text, "stale") || strings.Contains(text, "age")):
		return "vulnerability database may be stale; run sekscan db update with the same --home/--config"
	case strings.Contains(text, "database") && (strings.Contains(text, "not found") || strings.Contains(text, "does not exist") || strings.Contains(text, "unable to load") || strings.Contains(text, "no such file")):
		return "vulnerability database may be missing or incompatible; run sekscan prepare --all --yes with the same workspace"
	case strings.Contains(text, "x509:"), strings.Contains(text, "certificate"):
		return "TLS/certificate validation failed; check the trusted CA and proxy configuration (do not disable verification)"
	case strings.Contains(text, "unauthorized"), strings.Contains(text, "authentication required"), strings.Contains(text, "status code: 401"), strings.Contains(text, "status code: 403"):
		return "upstream authentication/authorization failed; check explicit registry credentials and release access"
	case strings.Contains(text, "no such host"), strings.Contains(text, "connection refused"), strings.Contains(text, "i/o timeout"), strings.Contains(text, "network is unreachable"):
		return "network/DNS connection failed; check proxy/egress access, or prepare the workspace on a connected machine"
	case strings.Contains(text, "permission denied"), strings.Contains(text, "access is denied"):
		return "access denied; check executable permissions and target/cache directory access"
	case strings.Contains(text, "config") && (strings.Contains(text, "yaml") || strings.Contains(text, "unmarshal") || strings.Contains(text, "parse")):
		return "scanner configuration parsing failed; check the selected native configuration against the installed version"
	case strings.Contains(text, "no solution found"), strings.Contains(text, "no matching distribution"), strings.Contains(text, "no wheels"), strings.Contains(text, "does not have a wheel"):
		return "Python package resolution lacks compatible binary wheels or has conflicting constraints; inspect the private preparation diagnostics and supported platform/version pins"
	case strings.Contains(text, "no space left"):
		return "insufficient disk space for scanner data or output"
	}
	return "rerun with --diagnostic-stderr to save private troubleshooting output in logs; inspect locally before sharing"
}

// SaveStderr is opt-in. Raw diagnostics can contain secrets and must not be
// included in portable reports or shared-database artifacts.
func SaveStderr(dir, engine string, stderr []byte) (string, error) {
	return SaveDiagnostic(dir, engine, "stderr", stderr)
}

// SaveDiagnostic stores bounded, opt-in troubleshooting data, never a report artifact.
func SaveDiagnostic(dir, engine, kind string, stderr []byte) (string, error) {
	if len(stderr) == 0 {
		return "", nil
	}
	for _, name := range []string{engine, kind} {
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00\r\n") {
			return "", fmt.Errorf("invalid diagnostic name")
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	// Keep private files bounded even for scanners with very large structured errors.
	if len(stderr) > 256<<10 {
		stderr = append(append([]byte{}, stderr[:256<<10]...), []byte("\n[private diagnostic truncated]\n")...)
	}
	f, err := os.CreateTemp(dir, engine+"-"+kind+"-*.private.log")
	if err != nil {
		return "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if err = f.Chmod(0600); err != nil {
		return "", err
	}
	if _, err = f.Write(stderr); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

// GoFailureHint classifies known package-loading failures without copying paths,
// module names, source snippets, URLs or credentials into the shared report.
// It is a hint, not an assertion that this is the only failing condition.
func GoFailureHint(output []byte) string {
	text := strings.ToLower(string(output))
	switch {
	case strings.Contains(text, "unrecognized vulndb format"):
		return "Go vulnerability database schema was not recognized; check index/modules.json and the scanner version probe"
	case strings.Contains(text, "module lookup disabled by goproxy=off"), strings.Contains(text, "cannot find module providing package"), strings.Contains(text, "no required module provides package"):
		return "Go dependency cache is incomplete or an import is unresolved; run sekscan prepare --go-module <module-directory> --yes with the same --home/--config, then review module dependencies"
	case strings.Contains(text, "missing go.sum entry"), strings.Contains(text, "updates to go.sum needed"), strings.Contains(text, "updates to go.mod needed"), strings.Contains(text, "-mod=readonly"):
		return "Go module metadata or checksums are incomplete for read-only analysis; prepare the module cache, review go.mod/go.sum, and run go mod tidy in a trusted development environment if needed"
	case strings.Contains(text, "requires go >="), strings.Contains(text, "requires newer go version"), strings.Contains(text, "built with go") && strings.Contains(text, "newer"), strings.Contains(text, "version of go used to build"):
		return "Go toolchain/analyzer version mismatch; update the workspace Go SDK and Go analyzers together, respecting reviewed version pins"
	case strings.Contains(text, "build constraints exclude all go files"), strings.Contains(text, "cgo is disabled"), strings.Contains(text, "requires cgo"):
		return "Go build constraints exclude required files; analysis uses CGO_ENABLED=0 and the current platform, so review CGO, build tags and target compatibility"
	case strings.Contains(text, "no packages matched"), strings.Contains(text, "matched no packages"), strings.Contains(text, "no go files"):
		return "Go analysis found no buildable packages; check the selected module, platform and build constraints"
	}
	return ""
}
