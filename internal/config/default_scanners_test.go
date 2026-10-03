package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultSourceSuite(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.Checks.Gitleaks || !c.Checks.Actionlint || len(c.EffectiveExtensions()) != 4 {
		t.Fatal("default suite is disabled")
	}
	seen := map[string]bool{}
	for _, e := range c.EffectiveExtensions() {
		if !e.Required || !e.Builtin || !e.Offline || !e.RedactMessages || e.When == "" {
			t.Fatal(e)
		}
		seen[e.Name] = true
	}
	for _, n := range []string{"hadolint", "zizmor", "govulncheck", "gosec"} {
		if !seen[n] {
			t.Fatal(n)
		}
	}
}
func TestDefaultSuiteExplicitDisablesAndReplacement(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sekscan.json")
	os.WriteFile(p, []byte(`{"checks":{"hadolint":false,"gitleaks":false,"semgrep":false}}`), 0600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Checks.Gitleaks || len(c.EffectiveExtensions()) != 3 {
		t.Fatal(c.Checks)
	}
	c = Default()
	c.Extensions = []Extension{{Name: "hadolint", Executable: "test", Args: []string{"{target}"}, Targets: []string{"dir"}, OutputSource: "stdout", SuccessCodes: []int{0}}}
	if err = c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.EffectiveExtensions()) != 4 || c.EffectiveExtensions()[0].Builtin {
		t.Fatal("explicit replacement ignored")
	}
	c.Extensions = append(c.Extensions, c.Extensions[0])
	if c.Validate() == nil {
		t.Fatal("duplicate replacement accepted")
	}
}

func TestLegacyGoExtensionsInheritApplicabilityOnly(t *testing.T) {
	for _, tc := range []struct{ name, tool, when, want string }{
		{"govulncheck", "", "", "go-modules"},
		{"gosec", "", "", "go-modules"},
		{"team-go", "gosec", "", "go-modules"},
		{"team-go", "govulncheck", "", "go-modules"},
		{"gosec", "gosec", "all", "all"},
		{"custom", "", "", ""},
	} {
		t.Run(tc.name+tc.tool+tc.when, func(t *testing.T) {
			c := Default()
			c.Extensions = []Extension{{Name: tc.name, Tool: tc.tool, When: tc.when, Args: []string{"custom-args"}, Required: false, OutputSource: "stdout"}}
			for _, e := range c.EffectiveExtensions() {
				if e.Name == tc.name {
					if e.When != tc.want || e.Builtin || e.Required || e.Args[0] != "custom-args" || e.OutputSource != "stdout" {
						t.Fatal(e)
					}
				}
			}
			if c.Extensions[0].When != tc.when {
				t.Fatal("source configuration mutated")
			}
		})
	}
}
