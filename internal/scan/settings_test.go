package scan

import (
	"os"
	"path/filepath"
	"sekscan/internal/config"
	"sekscan/internal/runner"
	"strings"
	"testing"
)

func TestNativeSettingsAreExplicitAndHashed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "native.yaml")
	os.WriteFile(p, []byte("{}\n"), 0600)
	original := []string{"fs", "--config", "empty.yaml", "--format", "json", "--", "/target"}
	args, hash, e := configureInvocation(config.Tool{NativeConfig: p, ExtraArgs: []string{"--quiet"}}, original)
	if e != nil || len(hash) != 64 || strings.Join(args, " ") != "fs --config "+p+" --format json --quiet -- /target" || original[2] != "empty.yaml" {
		t.Fatal(args, hash, e)
	}
	if _, _, e = configureInvocation(config.Tool{NativeConfig: "missing"}, original); e == nil {
		t.Fatal("missing native config accepted")
	}
	if _, _, e = configureInvocation(config.Tool{NativeConfig: p}, []string{"fs"}); e == nil {
		t.Fatal("missing config slot accepted")
	}
}
func TestDatabaseCredentialsExcludedFromScannerEnvironment(t *testing.T) {
	t.Setenv("SEKSCAN_DB_DSN", "sensitive-one")
	t.Setenv("TEAM_DB_CREDENTIAL", "sensitive-two")
	got := strings.Join(runner.Without(runner.Environment(), "TEAM_DB_CREDENTIAL"), "\n")
	if strings.Contains(got, "sensitive-one") || strings.Contains(got, "sensitive-two") {
		t.Fatal("credential passed to scanner")
	}
}
