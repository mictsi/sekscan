package ui

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/url"
)

const DesignVersion = "3.0.2"
const DesignCommit = "687bcdcf67d56a3bdfe3bbc4ff1ae863239e8c8a"

// ShellOptions contains display context, never permissions or executable markup.
// Active names identify exact pages; a parent is emphasized separately.
type ShellOptions struct {
	Active, Project, Namespace, Driver string
	Portable                           bool
	OpenLabel, OpenURL                 string
	Breadcrumbs                        []Crumb
}

type Crumb struct {
	Label, URL string
	Project    bool
}

func (o ShellOptions) ProjectURL() string {
	return "/projects?" + url.Values{"project": {o.Project}}.Encode()
}
func (o ShellOptions) ProjectRunsURL() string { return o.ProjectURL() + "&tab=runs" }
func (o ShellOptions) ProjectAncestor() bool {
	return o.Project != "" && o.Active != "projects" && o.Active != "portfolio" && o.Active != "all-runs"
}
func (o ShellOptions) BrandURL() string {
	if o.Portable {
		return "#overview"
	}
	return "/"
}

//go:embed assets/shell.html
var shellSource string

var shellTemplate = template.Must(template.New("shell").Parse(shellSource))

// Shell renders a trusted template. All project names, URLs and labels are escaped
// by html/template. Callers must close the opened .app-area after their main region.
func Shell(o ShellOptions) (template.HTML, error) {
	var b bytes.Buffer
	if err := shellTemplate.Execute(&b, o); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil
}
