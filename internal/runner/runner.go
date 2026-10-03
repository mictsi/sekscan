// Package runner executes explicit argv vectors. It never invokes a shell.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Request struct {
	Executable   string
	Args         []string
	Dir          string
	Env          []string
	Timeout      time.Duration
	MaxOutput    int64
	SuccessCodes []int
}
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}
type Executor interface {
	Run(context.Context, Request) (Result, error)
}
type OSExecutor struct{}
type cappedWriter struct {
	b        bytes.Buffer
	max      int64
	overflow bool
	truncate bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	n := len(p)
	remaining := w.max - int64(w.b.Len())
	if remaining < 0 {
		remaining = 0
	}
	if int64(n) > remaining {
		w.overflow = true
		w.b.Write(p[:int(remaining)])
		if w.truncate {
			return n, nil
		}
		return int(remaining), fmt.Errorf("scanner output exceeds configured limit")
	}
	return w.b.Write(p)
}
func (OSExecutor) Run(parent context.Context, r Request) (Result, error) {
	if r.Timeout <= 0 {
		r.Timeout = 15 * time.Minute
	}
	if r.MaxOutput <= 0 {
		r.MaxOutput = 256 << 20
	}
	ctx, cancel := context.WithTimeout(parent, r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Executable, r.Args...)
	cmd.Dir = r.Dir
	cmd.Env = r.Env
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	configureProcess(cmd)
	cmd.WaitDelay = 3 * time.Second
	out := &cappedWriter{max: r.MaxOutput}
	stderr := &cappedWriter{max: 65536, truncate: true}
	cmd.Stdout = out
	cmd.Stderr = stderr
	cmd.Stdin = nil
	start := time.Now()
	err := cmd.Run()
	result := Result{Stdout: out.b.Bytes(), Stderr: stderr.b.Bytes(), Duration: time.Since(start)}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	} else {
		result.ExitCode = -1
	}
	if ctx.Err() != nil {
		return result, fmt.Errorf("scanner cancelled or timed out: %w", ctx.Err())
	}
	if out.overflow {
		return result, fmt.Errorf("scanner output exceeded %d bytes", r.MaxOutput)
	}
	codes := r.SuccessCodes
	if len(codes) == 0 {
		codes = []int{0}
	}
	if _, ok := err.(*exec.ExitError); err == nil || ok {
		for _, c := range codes {
			if result.ExitCode == c {
				return result, nil
			}
		}
	}
	// Scanner stderr can contain secrets. Only a fixed diagnostic hint is propagated.
	return result, fmt.Errorf("scanner execution failed (exit %d): %s; raw stderr withheld", result.ExitCode, FailureHint(result.Stderr))
}

// Environment strips inherited scanner policy knobs; registry credentials remain usable.
func Environment(extra ...string) []string {
	out := []string{}
	allowed := map[string]bool{"TRIVY_USERNAME": true, "TRIVY_PASSWORD": true, "TRIVY_REGISTRY_TOKEN": true, "SYFT_REGISTRY_AUTH_AUTHORITY": true, "SYFT_REGISTRY_AUTH_USERNAME": true, "SYFT_REGISTRY_AUTH_PASSWORD": true, "GRYPE_REGISTRY_AUTH_USERNAME": true, "GRYPE_REGISTRY_AUTH_PASSWORD": true}
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		upper := strings.ToUpper(k)
		skip := strings.HasPrefix(upper, "SEKSCAN_") && upper != "SEKSCAN_FIXTURE_DIR" && upper != "SEKSCAN_FAIL_ENGINE" || upper == "GITHUB_TOKEN" || upper == "GH_TOKEN" || upper == "SYSTEM_ACCESSTOKEN" || upper == "AZURE_DEVOPS_EXT_PAT" || upper == "GOROOT" || upper == "GOVULNDB" || upper == "GITHUB_AUTHENTICATION_TOKEN"
		for _, p := range []string{"SYFT_", "GRYPE_", "TRIVY_", "GITLEAKS_", "GOSEC_", "SEMGREP_", "ZIZMOR_", "HADOLINT_", "UV_", "PIP_", "PYTHON"} {
			if strings.HasPrefix(upper, p) && !allowed[upper] {
				skip = true
			}
		}
		if !skip {
			out = append(out, e)
		}
	}
	// Replace, rather than append duplicate environment keys.
	for _, e := range extra {
		k, _, _ := strings.Cut(e, "=")
		for i := len(out) - 1; i >= 0; i-- {
			existingKey, _, _ := strings.Cut(out[i], "=")
			if strings.EqualFold(existingKey, k) {
				out = append(out[:i], out[i+1:]...)
			}
		}
		out = append(out, e)
	}
	return out
}

var _ io.Writer = (*cappedWriter)(nil)

// Without removes explicitly sensitive keys, including a user-selected database DSN.
func Without(env []string, keys ...string) []string {
	denied := map[string]bool{}
	for _, k := range keys {
		denied[strings.ToUpper(k)] = true
	}
	out := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if !denied[strings.ToUpper(k)] {
			out = append(out, e)
		}
	}
	return out
}

// Merge replaces environment keys in an already filtered environment.
func Merge(env []string, values ...string) []string {
	out := append([]string{}, env...)
	for _, value := range values {
		key, _, _ := strings.Cut(value, "=")
		out = Without(out, key)
		out = append(out, value)
	}
	return out
}
