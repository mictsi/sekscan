package ui

import (
	"regexp"
	"strings"
	"testing"
)

func TestShellNavigation(t *testing.T) {
	cases := []struct {
		name    string
		options ShellOptions
		label   string
	}{
		{"portfolio", ShellOptions{Active: "portfolio"}, "Portfolio"},
		{"projects", ShellOptions{Active: "projects"}, "Projects"},
		{"all runs", ShellOptions{Active: "all-runs"}, "All runs"},
		{"project dashboard", ShellOptions{Active: "project-overview", Project: "owner/repo"}, "Dashboard"},
		{"project runs", ShellOptions{Active: "project-runs", Project: "owner/repo"}, "Runs"},
		{"comparison", ShellOptions{Project: "owner/repo", OpenLabel: "Run comparison", OpenURL: "/compare?base=a&head=b"}, "Run comparison"},
		{"stored report", ShellOptions{Project: "owner/repo", OpenLabel: "Scan report", OpenURL: "/scans/a"}, "Scan report"},
		{"portable report", ShellOptions{Portable: true}, "Scan report"},
	}
	current := regexp.MustCompile(`<a[^>]+aria-current="page"[^>]*>[\s\S]*?<span class="sk-side-nav__label">([^<]+)</span></a>`)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rendered, err := Shell(tc.options)
			if err != nil {
				t.Fatal(err)
			}
			body := string(rendered)
			matches := current.FindAllStringSubmatch(body, -1)
			if len(matches) != 1 || matches[0][1] != tc.label {
				t.Fatalf("current destination: %v", matches)
			}
			if tc.options.Project != "" && (!strings.Contains(body, `aria-controls="project-nav-children"`) || !strings.Contains(body, `id="project-nav-children"`)) {
				t.Fatal("missing independently controlled children")
			}
			if tc.options.ProjectAncestor() && !strings.Contains(body, "data-active-ancestor") {
				t.Fatal("parent not distinguished from current page")
			}
			if tc.options.Portable && (strings.Contains(body, `href="/projects`) || strings.Contains(body, `href="/?tab=`)) {
				t.Fatal("portable report exposes unavailable history links")
			}
			for _, marker := range []string{`data-nav-trigger`, `data-nav-close`, `data-nav-scrim`, `aria-controls="app-navigation"`, `aria-label="Appearance"`} {
				if !strings.Contains(body, marker) {
					t.Fatal("missing shell control", marker)
				}
			}
		})
	}
}

func TestShellEscapesContext(t *testing.T) {
	value := `"><script>alert(1)</script>`
	rendered, err := Shell(ShellOptions{Project: value, Driver: value, Namespace: value, OpenLabel: value, OpenURL: "javascript:alert(1)", Breadcrumbs: []Crumb{{Label: value, URL: "javascript:alert(1)"}}})
	if err != nil {
		t.Fatal(err)
	}
	body := string(rendered)
	if strings.Contains(body, "<script>") || strings.Contains(body, `href="javascript:`) {
		t.Fatal("unsafe context escaped template")
	}
	if !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "#ZgotmplZ") {
		t.Fatal("missing escaping or unsafe URL rejection")
	}
	if !strings.Contains(body, "project=%22%3E%3Cscript%3E") {
		t.Fatal("project URL not encoded")
	}
}

func TestDesignAssetContract(t *testing.T) {
	if DesignVersion != "3.0.2" || len(DesignCommit) != 40 {
		t.Fatal("unversioned design reference")
	}
	for _, marker := range []string{"--sk-layout-header-height: 3rem", "--sk-layout-nav-width: 17rem", "grid-template-rows: subgrid", "sk-field__hint", "sk-side-nav__children", "border-inline-start", "forced-colors: active", "prefers-reduced-motion"} {
		if !strings.Contains(CSS, marker) {
			t.Fatal("missing design contract", marker)
		}
	}
	for _, source := range []string{CSS, JS, shellSource} {
		if strings.Contains(source, "fonts.googleapis.com") || strings.Contains(source, "https://cdn.") {
			t.Fatal("runtime external dependency")
		}
	}
}
