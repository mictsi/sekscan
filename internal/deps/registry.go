package deps

import (
	"context"
	"fmt"
	"sekscan/internal/config"
	"sort"
	"strconv"
	"strings"
	"time"
)

func NewConfigured(dir string, c config.Config) *Manager {
	if dir == "" {
		dir = c.Paths.Bin
	}
	c = c.WithoutSemgrep()
	m := New(dir)
	m.Portable = c.Portable
	m.CacheDir = c.Paths.Cache
	m.MaxDBAge = c.MaxDBAge
	if c.DiagnosticStderr {
		m.DiagnosticDir = c.Paths.Logs
	}
	m.LogDir = c.Paths.Logs
	m.Tools = c.Tools
	m.DenyEnv = []string{c.Storage.DSNEnv}
	return m
}
func (m *Manager) repository(name string) (string, bool) {
	if t, ok := m.Tools[name]; ok && t.Install != nil {
		return t.Install.Repository, true
	}
	r, ok := Repositories[name]
	return r, ok
}
func (m *Manager) executableName(name string) string {
	if t, ok := m.Tools[name]; ok && t.Install != nil && t.Install.Executable != "" {
		name = t.Install.Executable
	}
	return binName(name, m.GOOS)
}
func (m *Manager) assetNames(name, version string) (string, string, error) {
	if t, ok := m.Tools[name]; ok && t.Install != nil {
		raw, ok := t.Install.Assets[m.GOOS+"/"+m.GOARCH]
		if !ok {
			return "", "", fmt.Errorf("no configured release asset for %s/%s", m.GOOS, m.GOARCH)
		}
		replace := strings.NewReplacer("{version}", strings.TrimPrefix(version, "v"), "{os}", m.GOOS, "{arch}", m.GOARCH)
		return replace.Replace(raw), replace.Replace(t.Install.Checksums), nil
	}
	a, e := AssetName(name, version, m.GOOS, m.GOARCH)
	if name == "hadolint" {
		return a, "checksums.sha256", e
	}
	if name == "zizmor" || name == "uv" {
		return a, "", e
	}
	return a, name + "_" + strings.TrimPrefix(version, "v") + "_checksums.txt", e
}
func ToolNames(c config.Config, all bool) []string {
	c = c.WithoutSemgrep()
	if !all {
		return c.RequiredTools()
	}
	names := []string{}
	for n := range c.Tools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

type UpdateStatus struct {
	Name            string    `json:"name"`
	Installed       string    `json:"installed,omitempty"`
	Latest          string    `json:"latest,omitempty"`
	Configured      string    `json:"configured"`
	State           string    `json:"state"`
	UpdateAvailable bool      `json:"update_available"`
	CheckedAt       time.Time `json:"checked_at"`
	Error           string    `json:"error,omitempty"`
}

func (m *Manager) CheckUpdate(ctx context.Context, name string, t config.Tool) UpdateStatus {
	u := UpdateStatus{Name: name, Configured: t.Version, State: "unknown", CheckedAt: time.Now().UTC()}
	// Check the actual installation independently of a policy pin.
	probe := t
	probe.Version = "latest"
	probe.SHA256 = ""
	st := m.Inspect(ctx, name, probe)
	if st.Error == "" {
		u.Installed = st.Version
	}
	if t.Install == nil && (name == "go" || name == "govulncheck") {
		version, err := m.runtimeVersion(ctx, name, "latest")
		if err != nil {
			u.Error = err.Error()
			return u
		}
		u.Latest = version
	} else {
		if _, ok := m.repository(name); !ok {
			u.State = "managed-bundle"
			if st.Error != "" {
				u.State = "unavailable"
				u.Error = st.Error
			}
			return u
		}
		r, err := m.Release(ctx, name, "latest")
		if err != nil {
			u.Error = err.Error()
			return u
		}
		u.Latest = strings.TrimPrefix(r.Tag, "v")
	}
	if st.Error != "" {
		u.State = "unavailable"
		u.Error = st.Error
		return u
	}
	cmp, e := CompareVersions(u.Latest, u.Installed)
	if e != nil {
		u.Error = e.Error()
		return u
	}
	u.UpdateAvailable = cmp > 0
	u.State = "current"
	if cmp < 0 {
		u.State = "ahead"
	}
	if u.UpdateAvailable {
		u.State = "update-available"
	}
	if t.Version != "latest" && t.Version != "" && u.UpdateAvailable {
		u.State = "update-available-pinned"
	}
	return u
}

// CompareVersions implements SemVer precedence, ignoring build metadata.
func CompareVersions(a, b string) (int, error) {
	split := func(v string) ([]uint64, string, error) {
		v = strings.TrimPrefix(v, "v")
		if !config.ValidVersion(v) || v == "latest" {
			return nil, "", fmt.Errorf("invalid semantic version")
		}
		v, _, _ = strings.Cut(v, "+")
		core, pre, _ := strings.Cut(v, "-")
		parts := strings.Split(core, ".")
		nums := []uint64{}
		for _, s := range parts {
			n, e := strconv.ParseUint(s, 10, 64)
			if e != nil {
				return nil, "", e
			}
			nums = append(nums, n)
		}
		return nums, pre, nil
	}
	aa, ap, e := split(a)
	if e != nil {
		return 0, e
	}
	bb, bp, e := split(b)
	if e != nil {
		return 0, e
	}
	for i := range aa {
		if aa[i] > bb[i] {
			return 1, nil
		}
		if aa[i] < bb[i] {
			return -1, nil
		}
	}
	if ap == bp {
		return 0, nil
	}
	if ap == "" {
		return 1, nil
	}
	if bp == "" {
		return -1, nil
	}
	x, y := strings.Split(ap, "."), strings.Split(bp, ".")
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] == y[i] {
			continue
		}
		xn, xe := strconv.ParseUint(x[i], 10, 64)
		yn, ye := strconv.ParseUint(y[i], 10, 64)
		if xe == nil && ye == nil {
			if xn > yn {
				return 1, nil
			}
			return -1, nil
		}
		if xe == nil {
			return -1, nil
		}
		if ye == nil {
			return 1, nil
		}
		return strings.Compare(x[i], y[i]), nil
	}
	if len(x) > len(y) {
		return 1, nil
	}
	return -1, nil
}
