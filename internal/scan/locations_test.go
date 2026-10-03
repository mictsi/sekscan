package scan

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestZizmorLocationResolution(t *testing.T) {
	repo, cwd := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	writeInput(t, repo, ".github/workflows/ci.yml")
	writeInput(t, repo, "actions/my action/action.yml")
	file := filepath.Join(repo, ".github/workflows/ci.yml")
	action := filepath.Join(repo, "actions/my action/action.yml")
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(action)}
	if u.Path[0] != '/' {
		u.Path = "/" + u.Path
	}
	for _, tc := range []struct{ name, root, input, raw string }{
		{"absolute", repo, file, file},
		{"repository relative", repo, file, ".github/workflows/ci.yml"},
		{"dot relative", repo, file, "./.github/workflows/ci.yml"},
		{"input relative", repo, file, "ci.yml"},
		{"selected subdirectory", filepath.Join(repo, ".github"), file, ".github/workflows/ci.yml"},
		{"space in identifier", repo, action, "actions/my action/action.yml"},
		{"encoded file uri", repo, action, u.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := analyzerLocation("zizmor", tc.root, cwd, []string{tc.input}, tc.raw)
			if err != nil || got != tc.input {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
}

func TestZizmorNestedRepositoriesAndArchives(t *testing.T) {
	root, cwd := t.TempDir(), t.TempDir()
	// A .git file is a worktree marker; its contents are not executed or followed.
	writeInput(t, root, "nested/.git")
	writeInput(t, root, "nested/.github/workflows/ci.yml")
	input := filepath.Join(root, "nested/.github/workflows/ci.yml")
	p, err := analyzerLocation("zizmor", root, cwd, []string{input}, ".github/workflows/ci.yml")
	if err != nil || p != input {
		t.Fatal(p, err)
	}
	// GitHub archives have no .git marker. Resolve from the selected source root.
	writeInput(t, root, "archive/.github/workflows/ci.yml")
	input = filepath.Join(root, "archive/.github/workflows/ci.yml")
	p, err = analyzerLocation("zizmor", filepath.Join(root, "archive"), cwd, []string{input}, ".github/workflows/ci.yml")
	if err != nil || p != input {
		t.Fatal(p, err)
	}
}

func TestZizmorRejectsUnselectedAndUnsafeLocations(t *testing.T) {
	root, cwd := t.TempDir(), t.TempDir()
	writeInput(t, root, ".github/workflows/ci.yml")
	writeInput(t, root, "other/ci.yml")
	input := filepath.Join(root, ".github/workflows/ci.yml")
	for _, raw := range []string{"", "../.github/workflows/ci.yml", filepath.Join(cwd, "ci.yml"), "other/ci.yml", "https://example.test/ci.yml", "file://remote/share/ci.yml", "file:ci.yml", "file:///tmp/ci.yml?token=SECRET", "file:///tmp/ci.yml#fragment", "\\\\host\\share\\ci.yml", "\x00"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := analyzerLocation("zizmor", root, cwd, []string{input}, raw); err == nil {
				t.Fatalf("accepted %q", raw)
			}
		})
	}
	link := filepath.Join(root, "linked.yml")
	if err := os.Symlink(input, link); err == nil {
		if _, err := analyzerLocation("zizmor", root, cwd, []string{link}, link); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func TestOtherAnalyzerBases(t *testing.T) {
	root, cwd := t.TempDir(), t.TempDir()
	writeInput(t, root, "src/app.py")
	p, err := analyzerLocation("custom-sast", root, root, nil, "src/app.py")
	if err != nil || p != filepath.Join(root, "src/app.py") {
		t.Fatal(p, err)
	}
	p, err = analyzerLocation("gosec", root, filepath.Join(root, "module"), nil, "main.go")
	if err != nil || p != filepath.Join(root, "module/main.go") {
		t.Fatal(p, err)
	}
	if _, err = analyzerLocation("gosec", root, cwd, nil, "main.go"); err == nil {
		t.Fatal("outside cwd accepted")
	}
}
