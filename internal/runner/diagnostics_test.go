package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFailureHintsNeverEchoScannerText(t *testing.T) {
	for _, text := range []string{"invalid exclude relative glob", "unknown flag", "database is too old", "database not found", "x509: certificate error", "unauthorized", "no such host", "permission denied", "config yaml parse failed", "no space left", "arbitrary message"} {
		t.Run(text, func(t *testing.T) {
			hint := FailureHint([]byte(text + " SECRET_SENTINEL_VALUE"))
			if hint == "" || strings.Contains(hint, "SECRET_SENTINEL") {
				t.Fatal(hint)
			}
		})
	}
}
func TestPrivateStderrIsExplicitAndRestricted(t *testing.T) {
	root := t.TempDir()
	if name, err := SaveStderr(root, "syft", nil); err != nil || name != "" {
		t.Fatal(name, err)
	}
	name, err := SaveStderr(root, "syft", []byte("sensitive fixture"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(name)
	if err != nil || string(b) != "sensitive fixture" {
		t.Fatal(err)
	}
	st, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	if filepath.Dir(name) != root || !strings.HasSuffix(name, ".private.log") {
		t.Fatal(name)
	}
	if _, err = SaveStderr(root, "../escape", []byte("x")); err == nil {
		t.Fatal("escape accepted")
	}
}

func TestGoFailureHintsAreActionableAndPrivate(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"unrecognized vulndb format", "index/modules.json"},
		{"module lookup disabled by GOPROXY=off", "--go-module"},
		{"missing go.sum entry", "go.mod/go.sum"},
		{"updates to go.mod needed; to update it: go mod tidy", "read-only"},
		{"module requires go >= 1.27.0", "toolchain/analyzer"},
		{"build constraints exclude all Go files", "CGO_ENABLED=0"},
		{"warning: ./... matched no packages", "no buildable packages"},
		{"No solution found when resolving dependencies", "binary wheels"},
		{"unexpected argument '--no-registry'", "option"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			h := FailureHint([]byte(tc.text + " SECRET_SENTINEL"))
			if !strings.Contains(h, tc.want) || strings.Contains(h, "SECRET_SENTINEL") {
				t.Fatal(h)
			}
		})
	}
}

func TestPrivateDiagnosticKindAndBound(t *testing.T) {
	root := t.TempDir()
	for _, kind := range []string{"../x", "", ".", "..", "x\x00y", "x\ny"} {
		if _, err := SaveDiagnostic(root, "gosec", kind, []byte("private")); err == nil {
			t.Fatal(kind)
		}
	}
	p, err := SaveDiagnostic(root, "gosec", "processing-errors", []byte(strings.Repeat("x", 300<<10)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) > (257<<10) || !strings.Contains(string(b), "truncated") {
		t.Fatal(len(b), err)
	}
}
