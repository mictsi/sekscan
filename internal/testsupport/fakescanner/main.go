// fakescanner is exclusively a test fixture. It does not perform security analysis.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if os.Getenv("PRIVATE_GH_TOKEN_SENTINEL") != "" {
		fmt.Fprintln(os.Stderr, "Test detected credential forwarding")
		os.Exit(9)
	}
	tool := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	args := os.Args[1:]
	for _, a := range args {
		if a == "version" || a == "--version" || a == "-version" {
			fmt.Println("1.2.3")
			return
		}
	}
	if os.Getenv("SEKSCAN_FAIL_ENGINE") == tool {
		fmt.Fprintln(os.Stderr, "SECRET_SENTINEL_MUST_NOT_APPEAR")
		os.Exit(3)
	}
	fixture := os.Getenv("SEKSCAN_FIXTURE_DIR")
	if fixture == "" {
		fmt.Fprintln(os.Stderr, "test fixture directory is required")
		os.Exit(2)
	}
	if err := validateTarget(fixture, tool, args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	b, e := os.ReadFile(filepath.Join(fixture, tool+".json"))
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	switch tool {
	case "syft":
		directory := false
		for _, a := range args {
			if strings.HasPrefix(a, "dir:") {
				directory = true
			}
		}
		if directory {
			for i, a := range args {
				if a == "--exclude" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "./") {
					fmt.Fprintln(os.Stderr, "invalid directory exclusion: must be target-relative ./ pattern")
					os.Exit(1)
				}
			}
		}
		for i, a := range args {
			if a != "-o" || i+1 >= len(args) {
				continue
			}
			format, dest, ok := strings.Cut(args[i+1], "=")
			if !ok {
				continue
			}
			var content any
			if format == "cyclonedx-json" {
				content = map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []any{}, "metadata": map[string]any{"properties": []any{map[string]string{"name": "sekscan:test-fixture", "value": "synthetic, not a real SBOM"}}}}
			} else {
				content = map[string]any{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "synthetic-test-fixture", "documentNamespace": "https://example.invalid/test-sbom", "creationInfo": map[string]any{"creators": []string{"Tool: sekscan-test-fixture"}, "created": "2026-10-02T00:00:00Z"}, "packages": []any{}}
			}
			raw, _ := json.Marshal(content)
			if e = os.WriteFile(dest, raw, 0600); e != nil {
				os.Exit(2)
			}
		}
		os.Stdout.Write(b)
	case "trivy":
		scanners := ""
		for i, a := range args {
			if a == "--scanners" && i+1 < len(args) {
				scanners = args[i+1]
			}
		}
		var doc map[string]any
		json.Unmarshal(b, &doc)
		for _, raw := range doc["Results"].([]any) {
			r := raw.(map[string]any)
			for _, pair := range [][2]string{{"vuln", "Vulnerabilities"}, {"secret", "Secrets"}, {"misconfig", "Misconfigurations"}, {"license", "Licenses"}} {
				if !strings.Contains(scanners, pair[0]) {
					delete(r, pair[1])
				}
			}
		}
		json.NewEncoder(os.Stdout).Encode(doc)
	case "gitleaks":
		for i, a := range args {
			if a == "--report-path" && i+1 < len(args) {
				if e = os.WriteFile(args[i+1], b, 0600); e != nil {
					os.Exit(2)
				}
				return
			}
		}
		os.Exit(2)
	default:
		os.Stdout.Write(b)
	}
}

// Optional test instrumentation: fail instead of emitting a canned successful
// result when an invocation accidentally targets the current directory.
func validateTarget(fixture, tool string, args []string) error {
	b, err := os.ReadFile(filepath.Join(fixture, "expected-target.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var expected struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(b, &expected); err != nil {
		return err
	}
	if !filepath.IsAbs(expected.Target) || len(args) < 2 || args[len(args)-2] != "--" {
		return fmt.Errorf("fixture expected an absolute target after --")
	}
	actual := args[len(args)-1]
	switch tool {
	case "syft":
		if actual != "dir:"+expected.Target {
			return fmt.Errorf("Syft received wrong target %q", actual)
		}
	case "trivy", "gitleaks":
		if actual != expected.Target {
			return fmt.Errorf("%s received wrong target %q", tool, actual)
		}
	case "grype":
		if !strings.HasPrefix(actual, "sbom:") {
			return fmt.Errorf("Grype did not receive generated SBOM")
		}
		data, err := os.ReadFile(strings.TrimPrefix(actual, "sbom:"))
		if err != nil {
			return err
		}
		var doc struct {
			Source struct {
				Metadata struct {
					Path string `json:"path"`
				} `json:"metadata"`
			} `json:"source"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return err
		}
		if doc.Source.Metadata.Path != expected.Target {
			return fmt.Errorf("Grype received the wrong directory's SBOM")
		}
	default:
		return fmt.Errorf("unsupported test tool %q", tool)
	}
	marker, err := os.ReadFile(filepath.Join(expected.Target, "target-marker.txt"))
	if err != nil || string(marker) != "outside-target-fixture" {
		return fmt.Errorf("could not read external target marker")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if cwd == expected.Target {
		return fmt.Errorf("scanner used source directory as its working directory")
	}
	return nil
}
