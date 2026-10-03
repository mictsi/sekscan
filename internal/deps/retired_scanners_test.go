package deps

import (
	"context"
	"net/http"
	"sekscan/internal/config"
	"strings"
	"testing"
)

func TestRemovedScannerCannotInstallOrResolve(t *testing.T) {
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	c.Tools["semgrep"] = config.Tool{Version: "latest"}
	c.Tools["uv"] = config.Tool{Version: "latest"}
	m := NewConfigured("", c)
	m.Client = &http.Client{Transport: runtimeTransport(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network request"); return nil, nil })}
	for _, all := range []bool{false, true} {
		for _, n := range ToolNames(c, all) {
			if config.RemovedScanner(n) || n == "uv" {
				t.Fatal("removed prerequisite selected", n)
			}
		}
	}
	for _, n := range []string{"semgrep", "pysemgrep", "semgrep-core"} {
		t.Run(n, func(t *testing.T) {
			if _, err := m.Install(context.Background(), n, config.Tool{Version: "latest"}); err == nil || !strings.Contains(err.Error(), "removed") {
				t.Fatal(err)
			}
			if _, _, err := m.resolve(n, config.Tool{Version: "latest"}); err == nil || !strings.Contains(err.Error(), "removed") {
				t.Fatal(err)
			}
			if _, err := m.ImportBundle(context.Background(), n, "1.2.3", t.TempDir(), "tool", nil); err == nil || !strings.Contains(err.Error(), "removed") {
				t.Fatal(err)
			}
		})
	}
	if _, err := m.runtimeVersion(context.Background(), "semgrep", "latest"); err == nil {
		t.Fatal("retired runtime queried")
	}
	if _, err := PublicDownload(context.Background(), m.Client, "https://pypi.org/pypi/semgrep/json", 100); err == nil {
		t.Fatal("retired endpoint accepted")
	}
}
