package batch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func manifestFile(t *testing.T, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "batch.json")
	if e := os.WriteFile(p, []byte(value), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestMixedManifest(t *testing.T) {
	p := manifestFile(t, `{"version":1,"defaults":{"gitleaks":true,"offline":true},"projects":[{"project":"Local app","path":"../source files","settings":{"offline":false}},{"repo_url":"https://github.com/Mictsi/SekuraDesignMCP.git","ref":"feature/ui","subdir":"src/"}]}`)
	_, jobs, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if len(jobs) != 2 || jobs[0].Path != filepath.Clean(filepath.Join(filepath.Dir(p), "../source files")) || !Enabled(jobs[0].Settings.Gitleaks) || Enabled(jobs[0].Settings.Offline) {
		t.Fatal(jobs)
	}
	if jobs[1].Project != "mictsi/sekuradesignmcp" || jobs[1].Subdir != "src" || !Enabled(jobs[1].Settings.Offline) {
		t.Fatal(jobs[1])
	}
}
func TestRejectInvalidManifest(t *testing.T) {
	cases := []string{
		`null`, `[]`, `{"version":2,"projects":[{"project":"x","path":"."}]}`,
		`{"version":1,"projects":[]}`, `{"version":1,"version":1,"projects":[]}`,
		`{"version":1,"projects":[{"path":"."}]}`,
		`{"version":1,"projects":[{"project":"x","path":".","repo_url":"o/r"}]}`,
		`{"version":1,"projects":[{"project":"x","path":".","repo_url":""}]}`,
		`{"version":1,"projects":[{"project":"x","path":".","ref":""}]}`,
		`{"version":1,"projects":[{"project":"x","path":".","subdir":""}]}`,
		`{"version":1,"projects":[{"repo_url":"o/r","path":""}]}`,
		`{"version":1,"projects":[{"repo_url":"o/r","command":"sh"}]}`,
		`{"version":1,"defaults":{"offline":null},"projects":[{"repo_url":"o/r"}]}`,
		`{"version":1,"defaults":{"offline":false,"offline":true},"projects":[{"repo_url":"o/r"}]}`,
		`{"version":1,"projects":[{"repo_url":"o/r"},{"repo_url":"O/R"}]}`,
		`{"version":1,"projects":[{"project":"abc ","path":"."}]}`,
		`{"version":1,"projects":[{"repo_url":"https://token@github.com/o/r"}]}`,
		`{"version":1,"projects":[{"repo_url":"o/r","subdir":"../outside"}]}`,
		`{"version":1,"projects":[{"repo_url":"o/r","settings":{"timeout":"10m"}}]}`,
		`{"version":1,"projects":[{"repo_url":"o/r"}]} {}`,
	}
	for i, v := range cases {
		t.Run(strings.ReplaceAll(v, "/", "_"), func(t *testing.T) {
			if _, _, e := Load(manifestFile(t, v)); e == nil {
				t.Fatalf("accepted case %d", i)
			}
		})
	}
}
func TestBoundsAndExplicitOverrides(t *testing.T) {
	if _, _, e := Load(manifestFile(t, strings.Repeat(" ", (4<<20)+1))); e == nil {
		t.Fatal("size")
	}
	entries := make([]Entry, MaxProjects+1)
	if _, e := (Manifest{Version: 1, Projects: entries}).Plan(""); e == nil {
		t.Fatal("project count")
	}
	yes, no := true, false
	s := Merge(Settings{Offline: &yes, Gitleaks: &yes}, Settings{Gitleaks: &no})
	if !Enabled(s.Offline) || Enabled(s.Gitleaks) {
		t.Fatal(s)
	}
}

func TestStrictSchemaKeyCaseAndDepth(t *testing.T) {
	for _, body := range []string{
		`{"Version":1,"projects":[{"project":"app","path":"."}]}`,
		`{"version":1,"defaults":{"Offline":true},"projects":[{"project":"app","path":"."}]}`,
		`{"version":1,"projects":[{"project":"app","path":".","Ref":"main"}]}`,
		`{"extra":` + strings.Repeat("[", 40) + `true` + strings.Repeat("]", 40) + `}`,
	} {
		if err := RejectAmbiguousJSON([]byte(body)); err == nil {
			t.Fatal("ambiguous/deep JSON accepted", body)
		}
	}
}
