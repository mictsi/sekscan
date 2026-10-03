package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sekscan/internal/model"
)

// HasTargetPrefix recognizes explicit target types for the target-first CLI.
// Unknown words and bare paths must not silently turn into scan commands.
func HasTargetPrefix(input string) bool {
	kind, _, ok := strings.Cut(input, ":")
	return ok && validTargetKind(kind)
}

func validTargetKind(kind string) bool {
	switch kind {
	case "dir", "rootfs", "image", "docker-archive", "oci-archive", "oci-layout", "sbom":
		return true
	default:
		return false
	}
}

func ParseTarget(input string) (model.Target, error) {
	kind, value := "dir", input
	if k, v, ok := strings.Cut(input, ":"); ok {
		if validTargetKind(k) {
			kind, value = k, v
		} else if len(k) != 1 {
			return model.Target{}, fmt.Errorf("unknown target type %q", k)
		}
	}
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return model.Target{}, fmt.Errorf("invalid scan target")
	}
	t := model.Target{Kind: kind, Value: value, Identity: value}
	if kind == "image" {
		if strings.HasPrefix(value, "-") || strings.Contains(value, "://") || strings.ContainsAny(value, " \t") {
			return t, fmt.Errorf("image must be an OCI image reference without embedded credentials or URL scheme")
		}
		return t, nil
	}
	absolute, e := filepath.Abs(value)
	if e != nil {
		return t, e
	}
	absolute, e = filepath.EvalSymlinks(absolute)
	if e != nil {
		return t, e
	}
	st, e := os.Stat(absolute)
	if e != nil {
		return t, e
	}
	wantDir := kind == "dir" || kind == "rootfs" || kind == "oci-layout"
	if wantDir && !st.IsDir() {
		return t, fmt.Errorf("%s target must be a directory", kind)
	}
	if !wantDir && !st.Mode().IsRegular() {
		return t, fmt.Errorf("%s target must be a regular file", kind)
	}
	t.Value = absolute
	t.Identity = filepath.Base(absolute)
	return t, nil
}
func syftTarget(t model.Target) string {
	switch t.Kind {
	case "rootfs":
		return "dir:" + t.Value
	case "image":
		return t.Value
	case "oci-layout":
		return "oci-dir:" + t.Value
	default:
		return t.Kind + ":" + t.Value
	}
}
func relativeLocations(r *model.Report) {
	if r.Target.Kind != "dir" && r.Target.Kind != "rootfs" {
		return
	}
	fix := func(locations []model.Location) {
		for i := range locations {
			p := locations[i].Path
			if filepath.IsAbs(p) {
				rel, e := filepath.Rel(r.Target.Value, p)
				if e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					locations[i].Path = filepath.ToSlash(rel)
				}
			}
		}
	}
	for i := range r.Components {
		fix(r.Components[i].Locations)
		for j := range r.Components[i].Licenses {
			fix(r.Components[i].Licenses[j].Locations)
		}
	}
	for i := range r.Findings {
		fix(r.Findings[i].Locations)
	}
}
