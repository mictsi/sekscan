package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultValid(t *testing.T) {
	if e := Default().Validate(); e != nil {
		t.Fatal(e)
	}
}
func TestStrictConfiguration(t *testing.T) {
	for _, s := range []string{`{"version":99}`, `{"typo":true}`, `{"policy":{"fail_at":"hgh"}}`, `{} {}`, `{"exceptions":[{"id":"x"}]}`, `{"tools":{"syft":{"version":"../../bad"}}}`, `{"exclude":["../secret"]}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		os.WriteFile(path, []byte(s), 0600)
		if _, e := Load(path); e == nil {
			t.Fatal("accepted", s)
		}
	}
}
func TestRelativeToolPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"tools":{"syft":{"path":"bin/syft","version":"latest"}}}`), 0600)
	c, e := Load(path)
	if e != nil || c.Tools["syft"].Path != filepath.Join(dir, "bin/syft") {
		t.Fatal(c, e)
	}
}
