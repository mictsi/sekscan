package deps

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sekscan/internal/config"
)

func TestKICSBundleInstall(t *testing.T) {
	binary := tarArchive(t, []string{"kics"}, 0)
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, name := range []string{"assets/queries/test/query.rego", "assets/libraries/common.rego", "assets/libraries/common.json"} {
		w, _ := z.Create(name)
		w.Write([]byte("rule fixture"))
	}
	z.Close()
	rules := buf.Bytes()
	binHash := fmt.Sprintf("%x", sha256.Sum256(binary))
	rulesHash := fmt.Sprintf("%x", sha256.Sum256(rules))
	var base string
	bad := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tags/v2.1.20"):
			digest := rulesHash
			if bad {
				digest = strings.Repeat("0", 64)
			}
			json.NewEncoder(w).Encode(Release{Tag: "v2.1.20", Assets: []Asset{
				{Name: "kics_2.1.20_linux_amd64.tar.gz", URL: base + "/binary", Digest: "sha256:" + binHash},
				{Name: "checksums.txt", URL: base + "/checksums"},
				{Name: "extracted-info.zip", URL: base + "/rules", Digest: "sha256:" + digest},
			}})
		case r.URL.Path == "/binary":
			w.Write(binary)
		case r.URL.Path == "/rules":
			w.Write(rules)
		case r.URL.Path == "/checksums":
			fmt.Fprintln(w, binHash+"  kics_2.1.20_linux_amd64.tar.gz")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base = server.URL
	c := config.Default()
	c.ResolvePaths(t.TempDir())
	m := NewConfigured("", c)
	m.APIBase, m.Client, m.GOOS, m.GOARCH = base, server.Client(), "linux", "amd64"
	installed, err := m.Install(context.Background(), "kics", c.Tools["kics"])
	if err != nil || len(installed.Files) != 4 {
		t.Fatal(installed, err)
	}
	tool := c.Tools["kics"]
	tool.SHA256 = installed.ArchiveSHA256
	if _, err = m.Install(context.Background(), "kics", tool); err != nil {
		t.Fatal("locked reinstall", err)
	}
	if _, _, err = m.resolve("kics", tool); err != nil {
		t.Fatal(err)
	}
	bad = true
	if _, err = m.Install(context.Background(), "kics", tool); err == nil {
		t.Fatal("unverified rules installed")
	}
	if _, _, err = m.resolve("kics", tool); err != nil {
		t.Fatal("failed download damaged installation", err)
	}
	os.WriteFile(filepath.Join(m.Dir, "kics", "2.1.20", "assets", "libraries", "common.rego"), []byte("tampered"), 0600)
	if _, _, err = m.resolve("kics", tool); err == nil {
		t.Fatal("modified rules accepted")
	}
}

func TestKICSPlatforms(t *testing.T) {
	for _, os := range []string{"linux", "darwin", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name, err := AssetName("kics", "v2.1.20", os, arch)
			ext := ".tar.gz"
			if os == "windows" {
				ext = ".zip"
			}
			if err != nil || name != "kics_2.1.20_"+os+"_"+arch+ext {
				t.Fatal(name, err)
			}
		}
	}
}
