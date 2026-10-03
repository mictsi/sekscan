package batch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacySemgrepBatchSettingIsIgnored(t *testing.T) {
	file := filepath.Join(t.TempDir(), "projects.json")
	input := `{"version":1,"defaults":{"semgrep":true,"gosec":false},"projects":[{"project":"app","path":".","settings":{"semgrep":false,"hadolint":true}}]}`
	if err := os.WriteFile(file, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	m, jobs, err := Load(file)
	if err != nil || len(jobs) != 1 {
		t.Fatal(err)
	}
	if jobs[0].Settings.Gosec == nil || *jobs[0].Settings.Gosec || !Enabled(jobs[0].Settings.Hadolint) {
		t.Fatal(jobs)
	}
	for _, value := range []any{m, jobs} {
		b, _ := json.Marshal(value)
		if strings.Contains(string(b), "semgrep") {
			t.Fatal(string(b))
		}
	}
	b, _ := os.ReadFile(file)
	if string(b) != input {
		t.Fatal("manifest modified")
	}
}
func TestLegacyBatchStillStrict(t *testing.T) {
	for _, body := range []string{`{"semgrep":"true"}`, `{"semgrep":true,"misspelled":false}`} {
		var s Settings
		if err := json.Unmarshal([]byte(body), &s); err == nil {
			t.Fatal(body)
		}
	}
}
