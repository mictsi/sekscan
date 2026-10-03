package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func TestTargetsAndVersionValidation(t *testing.T) {
	all, e := parseTargets("all")
	if e != nil || len(all) != 6 {
		t.Fatal(all, e)
	}
	if _, e = parseTargets("linux/amd64,windows/amd64"); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"", "linux/386", "windows/386", "linux/amd64,linux/amd64", "all,linux/amd64"} {
		if _, e := parseTargets(v); e == nil {
			t.Fatal("accepted target", v)
		}
	}
	for _, v := range []string{"../../escape", "0.4.0 -X main.Bad=value", "0.4.0/evil", "01.2.3"} {
		if versionPattern.MatchString(v) {
			t.Fatal("unsafe version", v)
		}
	}
	for _, v := range []string{"0.4.0-preview", "v0.4.0", "1.2.3+build.1"} {
		if !versionPattern.MatchString(v) {
			t.Fatal("valid version", v)
		}
	}
}
func TestGoBuildEnvironmentCannotSelectTestDriver(t *testing.T) {
	env := buildEnv([]string{"GOOS=windows", "GOARCH=arm64", "CGO_ENABLED=1", "GOFLAGS=-tags=offline_sqltest", "GOWORK=/tmp/untrusted.work", "GOEXPERIMENT=bad", "KEEP=value"}, "linux/amd64")
	joined := "\n" + strings.Join(env, "\n") + "\n"
	for _, want := range []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=-mod=readonly", "GOWORK=off", "KEEP=value"} {
		if !strings.Contains(joined, "\n"+want+"\n") {
			t.Fatal(want, env)
		}
	}
	if strings.Contains(joined, "offline_sqltest") {
		t.Fatal("test flags leaked")
	}
}
func TestReadOnlyDependencyGraph(t *testing.T) {
	if _, e := parseModules([]byte(`{"Path":"sekscan","Main":true}{"Path":"example.org/lib","Version":"v1.2.3","Sum":"hash"}`)); e != nil {
		t.Fatal(e)
	}
	for _, b := range []string{"", `{"Path":"x","Replace":{"Path":"/tmp/x"}}`, `bad`} {
		if _, e := parseModules([]byte(b)); e == nil {
			t.Fatal("invalid graph accepted", b)
		}
	}
}
func productionBuildInfo() *debug.BuildInfo {
	info := &debug.BuildInfo{Path: "sekscan/cmd/sekscan", Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "amd64"}, {Key: "CGO_ENABLED", Value: "0"}}}
	for _, name := range []string{"modernc.org/sqlite", "github.com/jackc/pgx/v5", "github.com/microsoft/go-mssqldb"} {
		info.Deps = append(info.Deps, &debug.Module{Path: name, Version: "v1.0.0"})
	}
	return info
}
func TestProductionBinaryGate(t *testing.T) {
	if e := verifyBuildInfo(productionBuildInfo(), "linux/amd64"); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*debug.BuildInfo){
		func(i *debug.BuildInfo) { i.Path = "other/cmd" }, func(i *debug.BuildInfo) { i.Deps = i.Deps[:2] },
		func(i *debug.BuildInfo) {
			i.Settings = append(i.Settings, debug.BuildSetting{Key: "-tags", Value: "offline_sqltest"})
		},
		func(i *debug.BuildInfo) { i.Settings[2].Value = "1" }, func(i *debug.BuildInfo) { i.Settings[0].Value = "windows" },
		func(i *debug.BuildInfo) { i.Deps[0].Replace = &debug.Module{Path: "../local"} },
	} {
		info := productionBuildInfo()
		mutate(info)
		if e := verifyBuildInfo(info, "linux/amd64"); e == nil {
			t.Fatal("unsafe binary accepted", info)
		}
	}
}
func writeFixture(t *testing.T, root, name, contents string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if e := os.MkdirAll(filepath.Dir(p), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, []byte(contents), 0644); e != nil {
		t.Fatal(e)
	}
}
func releaseFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"README.md", "TESTING.md", "CHANGELOG.md", "go.mod", "go.sum", "examples/workspace-sekscan.json", "docs/SECURITY.md", "third_party/SekuraDesignMCP-LICENSE", "schema/sqlite.sql", "internal/workspace/defaults/syft.yaml", "cmd/sekscan/main.go", "testdata/fixture.json"} {
		writeFixture(t, root, name, "fixture\n")
	}
	template, e := os.ReadFile("README.md.tmpl")
	if e != nil {
		t.Fatal(e)
	}
	writeFixture(t, root, "scripts/release/README.md.tmpl", string(template))
	return root
}
func TestReleasePreflight(t *testing.T) {
	root := releaseFixture(t)
	o := options{Root: root, Out: filepath.Join(root, "dist", "0.4.0")}
	if e := preflight(o); e != nil {
		t.Fatal(e)
	}
	o.Out = filepath.Join(root, "docs", "release")
	if e := preflight(o); e == nil {
		t.Fatal("recursive packaging output accepted")
	}
	o.Out = filepath.Join(root, "dist", "0.4.0")
	if e := os.MkdirAll(o.Out, 0755); e != nil {
		t.Fatal(e)
	}
	if e := preflight(o); e == nil {
		t.Fatal("existing output accepted")
	}
	os.RemoveAll(o.Out)
	os.Remove(filepath.Join(root, "go.sum"))
	if e := preflight(o); e == nil || !strings.Contains(e.Error(), "go.sum") {
		t.Fatal("missing sums not rejected", e)
	}
}
func TestRuntimeZipContentsAndReproducibility(t *testing.T) {
	root := releaseFixture(t)
	epoch := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, target := range supportedTargets {
		t.Run(target, func(t *testing.T) {
			payload := filepath.Join(t.TempDir(), "sekscan-test")
			if e := os.Mkdir(payload, 0755); e != nil {
				t.Fatal(e)
			}
			exe := "sekscan"
			if strings.HasPrefix(target, "windows/") {
				exe += ".exe"
			}
			// A fixture file exercises packaging only, never the production binary gate.
			if e := os.WriteFile(filepath.Join(payload, exe), []byte("PACKAGING TEST FIXTURE; NOT A BINARY\n"), 0755); e != nil {
				t.Fatal(e)
			}
			o := options{Root: root, Version: "0.4.0-test", Timestamp: epoch}
			if e := populatePayload(o, payload, target, []module{{Path: "sekscan", Main: true}}); e != nil {
				t.Fatal(e)
			}
			if e := writeChecksums(payload, "SHA256SUMS.txt"); e != nil {
				t.Fatal(e)
			}
			a, b := filepath.Join(t.TempDir(), "a.zip"), filepath.Join(t.TempDir(), "b.zip")
			if e := zipTree(payload, a, epoch); e != nil {
				t.Fatal(e)
			}
			if e := zipTree(payload, b, epoch); e != nil {
				t.Fatal(e)
			}
			ah, _ := hashFile(a)
			bh, _ := hashFile(b)
			if ah != bh {
				t.Fatal("ZIP not deterministic")
			}
			z, e := zip.OpenReader(a)
			if e != nil {
				t.Fatal(e)
			}
			defer z.Close()
			names := map[string]*zip.File{}
			for _, f := range z.File {
				names[strings.TrimPrefix(f.Name, "sekscan-test/")] = f
			}
			for _, n := range []string{exe, "README.md", "readme.med", "SOURCE-README.md", "BUILD-INFO.json", "GO-MODULES.json", "SHA256SUMS.txt", "docs/SECURITY.md", "third_party/SekuraDesignMCP-LICENSE", "schema/sqlite.sql", "config/syft.yaml", "sekscan.json", "bin/", "cache/", "logs/", "data/"} {
				if _, ok := names[n]; !ok {
					t.Fatal("missing ZIP input", n)
				}
			}
			if names[exe].Mode().Perm()&0111 == 0 {
				t.Fatal("ZIP lost executable bit")
			}
			open, e := names["README.md"].Open()
			if e != nil {
				t.Fatal(e)
			}
			readme, _ := io.ReadAll(open)
			open.Close()
			if !bytes.Contains(readme, []byte("--project payments-api")) || !bytes.Contains(readme, []byte("--page-size")) || !bytes.Contains(readme, []byte(target)) {
				t.Fatal("README examples missing")
			}
			raw, _ := os.ReadFile(filepath.Join(payload, "BUILD-INFO.json"))
			var info map[string]any
			if json.Unmarshal(raw, &info) != nil || info["target"] != target || info["scanner_tools_bundled"] != false {
				t.Fatal("misleading build metadata")
			}
		})
	}
}
func TestSourceArchiveDoesNotIncludeWorkspaceData(t *testing.T) {
	root := releaseFixture(t)
	for _, name := range []string{"bin/private", "cache/vulnerability.db", "logs/private.log", "data/history.db", "sekscan.json", "dist/old.zip", "config/password.json"} {
		writeFixture(t, root, name, "DO NOT PACKAGE")
	}
	dest := filepath.Join(t.TempDir(), "source")
	if e := populateSource(root, dest); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"bin", "cache", "logs", "data", "sekscan.json", "dist", "config"} {
		if _, e := os.Stat(filepath.Join(dest, name)); !os.IsNotExist(e) {
			t.Fatal("workspace data copied", name)
		}
	}
	if _, e := os.Stat(filepath.Join(dest, "testdata/fixture.json")); e != nil {
		t.Fatal("tests would be broken in source package", e)
	}
}
func TestSymlinksAndChecksumMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require privileges")
	}
	root := t.TempDir()
	writeFixture(t, root, "file", "test")
	if e := os.Symlink(filepath.Join(root, "file"), filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	if e := copyPath(filepath.Join(root, "link"), filepath.Join(t.TempDir(), "copy")); e == nil {
		t.Fatal("symlink copied")
	}
	if e := zipTree(root, filepath.Join(t.TempDir(), "out.zip"), time.Now()); e == nil {
		t.Fatal("symlink archived")
	}
	writeFixture(t, root, "go.mod", "mod")
	writeFixture(t, root, "go.sum", "sum")
	a, _ := hashFile(filepath.Join(root, "go.mod"))
	b, _ := hashFile(filepath.Join(root, "go.sum"))
	if e := modulesUnchanged(root, a, b); e != nil {
		t.Fatal(e)
	}
	writeFixture(t, root, "go.sum", "modified")
	if e := modulesUnchanged(root, a, b); e == nil {
		t.Fatal("module mutation ignored")
	}
}
func TestHelperListsTargetsWithoutProductionModules(t *testing.T) {
	var out, errOut bytes.Buffer
	if e := run(context.Background(), []string{"--list-targets"}, &out, &errOut); e != nil || len(strings.Fields(out.String())) != len(supportedTargets) {
		t.Fatal(e, out.String(), errOut.String())
	}
}
func TestSourceDateEpoch(t *testing.T) {
	for _, v := range []string{"-1", "bad", "4354819200"} {
		if _, e := buildTime(v); e == nil {
			t.Fatal(v)
		}
	}
	a, e := buildTime("0")
	if e != nil || a.Unix() != 0 {
		t.Fatal(a, e)
	}
}

func TestWindowsARM64ReleaseTargetAndBinaryGate(t *testing.T) {
	targets, err := parseTargets("windows/arm64")
	if err != nil || len(targets) != 1 || targets[0] != "windows/arm64" {
		t.Fatal(targets, err)
	}
	info := productionBuildInfo()
	info.Settings[0].Value = "windows"
	info.Settings[1].Value = "arm64"
	if err = verifyBuildInfo(info, "windows/arm64"); err != nil {
		t.Fatal(err)
	}
	info.Settings[1].Value = "amd64"
	if err = verifyBuildInfo(info, "windows/arm64"); err == nil {
		t.Fatal("x64 mislabeled ARM64 accepted")
	}
}
