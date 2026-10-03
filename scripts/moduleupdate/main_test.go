package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSQLiteLibcRequirement(t *testing.T) {
	for _, raw := range []string{"require modernc.org/libc v1.77.1 // indirect\n", "require (\n modernc.org/libc v1.77.1\n)"} {
		v, e := requiredLibc([]byte(raw))
		if e != nil || v != "v1.77.1" {
			t.Fatal(v, e)
		}
	}
	if _, e := requiredLibc([]byte("module changed")); e == nil {
		t.Fatal("missing dependency not detected")
	}
}
func TestModuleJSONStream(t *testing.T) {
	out, e := modules([]byte("{\"Path\":\"main\",\"Main\":true}\n{\"Path\":\"x\",\"Version\":\"v1.0.0\",\"Update\":{\"Version\":\"v1.1.0\"}}\n"))
	if e != nil || len(out) != 2 || out[1].Update.Version != "v1.1.0" {
		t.Fatal(out, e)
	}
	if _, e := modules([]byte("invalid")); e == nil {
		t.Fatal("invalid JSON accepted")
	}
}

// The test executable acts as a deliberately failing go command. No modules
// are fetched; this checks that failed updates restore both module files.
func init() {
	if os.Getenv("SEKSCAN_FAKE_MODULE_GO") != "1" {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "get" {
		os.WriteFile("go.mod", []byte("broken update fixture"), 0644)
		os.WriteFile("go.sum", []byte("temporary checksum fixture"), 0644)
		os.Exit(1)
	}
	os.Exit(2)
}
func TestModuleUpdateRollback(t *testing.T) {
	root := t.TempDir()
	original := []byte("module rollback-fixture\ngo 1.23\n")
	if err := os.WriteFile(filepath.Join(root, "go.mod"), original, 0644); err != nil {
		t.Fatal(err)
	}
	fakeDir := t.TempDir()
	data, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	filename := "go"
	if runtime.GOOS == "windows" {
		filename += ".exe"
	}
	if err = os.WriteFile(filepath.Join(fakeDir, filename), data, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeDir)
	t.Setenv("SEKSCAN_FAKE_MODULE_GO", "1")
	if err = update(context.Background(), root); err == nil {
		t.Fatal("failed update reported success")
	}
	got, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil || string(got) != string(original) {
		t.Fatal("go.mod not restored", err)
	}
	if _, err = os.Stat(filepath.Join(root, "go.sum")); !os.IsNotExist(err) {
		t.Fatal("new go.sum not rolled back")
	}
	entries, _ := filepath.Glob(filepath.Join(root, ".module-update-backup-*"))
	if len(entries) != 0 {
		t.Fatal("rollback did not finish")
	}
}
