package scan

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sekscan/internal/config"
)

func TestGosecProcessingDiagnosticsAndZeroFiles(t *testing.T) {
	b := []byte(`{"Golang errors":{"private/module":[{"error":"module lookup disabled by GOPROXY=off SECRET_SENTINEL"}]},"Issues":[],"Stats":{"files":0}}`)
	_, err := ParseGosec(b)
	if err == nil || !strings.Contains(err.Error(), "--go-module") || strings.Contains(err.Error(), "SECRET_SENTINEL") || strings.Contains(err.Error(), "private/module") {
		t.Fatal(err)
	}
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	s := Scanner{Config: c, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.saveGosecDiagnostics(b)
	files, _ := filepath.Glob(filepath.Join(c.Paths.Logs, "*.private.log"))
	if len(files) != 0 {
		t.Fatal("diagnostics not opt-in")
	}
	s.Config.DiagnosticStderr = true
	s.saveGosecDiagnostics(b)
	files, _ = filepath.Glob(filepath.Join(c.Paths.Logs, "gosec-processing-errors-*.private.log"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	body, _ := os.ReadFile(files[0])
	var saved map[string]json.RawMessage
	if json.Unmarshal(body, &saved) != nil || saved["Issues"] != nil || !strings.Contains(string(body), "SECRET_SENTINEL") {
		t.Fatal("wrong private payload")
	}
	if len(saved) != 2 {
		t.Fatal(saved)
	}
}
