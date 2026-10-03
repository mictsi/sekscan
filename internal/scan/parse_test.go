package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", name+".json"))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestScannerParsing(t *testing.T) {
	in := NewInventory()
	if _, e := ParseSyft(fixture(t, "syft"), in); e != nil {
		t.Fatal(e)
	}
	if len(in.Components) != 10 {
		t.Fatal(len(in.Components))
	}
	findings, db, e := ParseGrype(fixture(t, "grype"), in)
	if e != nil || len(findings) != 4 || !json.Valid(db) {
		t.Fatal(e, len(findings))
	}
	trivy, e := ParseTrivy(fixture(t, "trivy"), in)
	if e != nil || len(trivy) != 6 {
		t.Fatal(e, len(trivy))
	}
	gitleaks, e := ParseGitleaks(fixture(t, "gitleaks"))
	if e != nil || len(gitleaks) != 1 {
		t.Fatal(e)
	}
	all, _ := json.Marshal(append(trivy, gitleaks...))
	if strings.Contains(string(all), "SECRET_SENTINEL") {
		t.Fatal("raw secret persisted")
	}
	if len(in.Components) != 10 {
		t.Fatalf("unnecessary duplicate components: %d", len(in.Components))
	}
}
func TestUnknownSchemasFailClosed(t *testing.T) {
	if _, e := ParseSyft([]byte(`{}`), NewInventory()); e == nil {
		t.Fatal("accepted missing inventory")
	}
	if _, _, e := ParseGrype([]byte(`{}`), NewInventory()); e == nil {
		t.Fatal("accepted missing matches")
	}
	if _, e := ParseTrivy([]byte(`{"SchemaVersion":99}`), NewInventory()); e == nil {
		t.Fatal("accepted unknown schema")
	}
	if _, e := ParseSARIF([]byte(`{"version":"2.1.0","runs":[{"invocations":[{"executionSuccessful":false}]}]}`), "test"); e == nil {
		t.Fatal("accepted failed SARIF invocation")
	}
}
func TestTargetValidation(t *testing.T) {
	dir := t.TempDir()
	target, e := ParseTarget("dir:" + dir)
	if e != nil || target.Kind != "dir" {
		t.Fatal(e)
	}
	for _, s := range []string{"image:--bad", "image:https://user:password@host/image", "unknown:value", "image:a\nb"} {
		if _, e = ParseTarget(s); e == nil {
			t.Fatal("accepted", s)
		}
	}
}
func FuzzScannerJSON(f *testing.F) {
	for _, b := range [][]byte{[]byte(`{}`), []byte(`{"artifacts":[]}`), []byte(`{"SchemaVersion":2}`)} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseSyft(b, NewInventory())
		_, _, _ = ParseGrype(b, NewInventory())
		_, _ = ParseTrivy(b, NewInventory())
		_, _ = ParseGitleaks(b)
		_, _ = ParseSARIF(b, "extension")
	})
}
