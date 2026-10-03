package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoveryPrecedenceAndCI(t *testing.T) {
	t.Setenv("SEKSCAN_CONFIG", "")
	root := t.TempDir()
	exeDir := t.TempDir()
	write := func(p string) {
		t.Helper()
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(`{}`), 0600); e != nil {
			t.Fatal(e)
		}
	}
	nested := filepath.Join(root, "config", "sekscan.json")
	write(nested)
	pick, e := Discover("", root, filepath.Join(exeDir, "sekscan"), false, false)
	if e != nil || pick.File != nested || pick.Root != root {
		t.Fatal(pick, e)
	}
	primary := filepath.Join(root, "sekscan.json")
	write(primary)
	pick, e = Discover("", root, "", false, false)
	if e != nil || pick.File != primary {
		t.Fatal(pick, e)
	}
	if _, e = Discover("", root, "", false, true); e == nil {
		t.Fatal("CI trusted discovered config")
	}
	pick, e = Discover(nested, "", "", false, true)
	if e != nil || pick.Source != "flag" || pick.Root != root {
		t.Fatal(pick, e)
	}
	t.Setenv("SEKSCAN_CONFIG", nested)
	pick, e = Discover("", root, "", false, true)
	if e != nil || pick.Source != "environment" {
		t.Fatal(pick, e)
	}
	pick, e = Discover(primary, root, "", false, false)
	if e != nil || pick.File != primary {
		t.Fatal(pick, e)
	}
	pick, e = Discover("", root, "", true, true)
	if e != nil || pick.File != "" {
		t.Fatal(pick, e)
	}
	if _, e = Discover(primary, root, "", true, false); e == nil {
		t.Fatal("mutually exclusive config flags")
	}
}
func TestSharedDefaultsAndNativePaths(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config", "postgres.json")
	os.MkdirAll(filepath.Dir(p), 0700)
	os.WriteFile(p, []byte(`{"storage":{"driver":"postgres"},"tools":{"syft":{"native_config":"syft.yaml"}}}`), 0600)
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	c.ResolvePaths(dir)
	if c.Storage.AutoMigrate || c.Paths.Bin != filepath.Join(dir, "bin") || c.Storage.Path != filepath.Join(dir, "data", "sekscan.db") || c.Tools["syft"].NativeConfig != filepath.Join(dir, "config", "syft.yaml") || c.Tools["syft"].Version != "latest" {
		t.Fatalf("bad defaults: %+v", c)
	}
}
func TestExtensionAndInstallValidation(t *testing.T) {
	for _, raw := range []string{
		`{"tools":{"bad":{"install":{"repository":"evil/repo","assets":{"linux/amd64":"../x"},"checksums":"checksums.txt"}}}}`,
		`{"tools":{"syft":{"extra_args":["--output=elsewhere"]}}}`,
		`{"extensions":[{"name":"x","executable":"x","args":[],"targets":["image"],"output_source":"stdout","success_codes":[0],"working_directory":"target"}]}`,
		`{"storage":{"dsn":"postgres://secret"}}`,
	} {
		p := filepath.Join(t.TempDir(), "sekscan.json")
		os.WriteFile(p, []byte(raw), 0600)
		if _, e := Load(p); e == nil {
			t.Fatal("accepted invalid config", raw)
		}
	}
	c := Default()
	c.Extensions = []Extension{{Name: "checks", Executable: "checker", Targets: []string{"dir"}, OutputSource: "stdout", SuccessCodes: []int{0}, WorkingDirectory: "target"}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
}
