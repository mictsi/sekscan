package deps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"sekscan/internal/config"
	"sekscan/internal/runner"
	"sekscan/internal/store"
)

// Environment is shared by version probes, scans and database preparation.
// Portable mode intentionally does not inherit user-home configuration or PATH
// helpers. Registry credentials can still be supplied explicitly in environment.
func (m *Manager) Environment(offline bool) ([]string, error) {
	cache := m.CacheDir
	if cache == "" {
		cache = filepath.Join(filepath.Dir(m.Dir), "cache")
	}
	cache, err := filepath.Abs(cache)
	if err != nil {
		return nil, err
	}
	age := m.MaxDBAge
	if age == "" {
		age = "120h"
	}
	extra := []string{
		"SYFT_CHECK_FOR_APP_UPDATE=false", "GRYPE_CHECK_FOR_APP_UPDATE=false",
		"GRYPE_DB_CACHE_DIR=" + filepath.Join(cache, "grype", "db"),
		"GRYPE_DB_VALIDATE_AGE=true", "GRYPE_DB_MAX_ALLOWED_BUILT_AGE=" + age,
		"GRYPE_DB_AUTO_UPDATE=" + strconv.FormatBool(!offline),
		"TRIVY_CACHE_DIR=" + filepath.Join(cache, "trivy"),
		"TRIVY_DISABLE_TELEMETRY=true",
		"SYFT_CACHE_DIR=" + filepath.Join(cache, "syft"),
	}
	if m.Portable {
		dirs := map[string]string{
			"HOME": "home", "USERPROFILE": "home", "XDG_CACHE_HOME": "xdg/cache",
			"XDG_CONFIG_HOME": "xdg/config", "XDG_DATA_HOME": "xdg/data",
			"APPDATA": "home/AppData/Roaming", "LOCALAPPDATA": "home/AppData/Local",
			"TMPDIR": "tmp", "TMP": "tmp", "TEMP": "tmp",
			"GOCACHE": "go/build", "GOMODCACHE": "go/mod", "GOPATH": "go",
			"GOTELEMETRYDIR": "go/telemetry",
		}
		keys := make([]string, 0, len(dirs))
		for key := range dirs {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			p := filepath.Join(cache, filepath.FromSlash(dirs[key]))
			if err := config.WithinDirectory(cache, p); err != nil {
				return nil, err
			}
			if err := os.MkdirAll(p, 0700); err != nil {
				return nil, err
			}
			extra = append(extra, key+"="+p)
		}
		paths := []string{}
		base, err := filepath.Abs(m.Dir)
		if err != nil {
			return nil, err
		}
		paths = append(paths, base)
		names := make([]string, 0, len(m.Tools))
		for name := range m.Tools {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			b, err := store.Read(filepath.Join(base, name, "current.json"), 16<<20)
			var installed Installed
			if err == nil && json.Unmarshal(b, &installed) == nil && installed.Name == name && config.ValidVersion(installed.Version) && installed.Version != "latest" {
				p := filepath.Join(base, name, installed.Version)
				if err := config.WithinDirectory(base, p); err != nil {
					return nil, err
				}
				if installed.Entrypoint != "" && safeBundlePath(installed.Entrypoint) {
					p = filepath.Dir(filepath.Join(p, filepath.FromSlash(installed.Entrypoint)))
				}
				if name == "go" && installed.Entrypoint != "" {
					extra = append(extra, "GOROOT="+filepath.Dir(p))
				}
				paths = append(paths, p)
			}
		}
		extra = append(extra, "PATH="+strings.Join(paths, string(os.PathListSeparator)), "GOTOOLCHAIN=local", "GOENV=off", "PYTHONNOUSERSITE=1")
	}
	if offline {
		extra = append(extra, "SYFT_JAVA_USE_NETWORK=false", "GOPROXY=off", "GOSUMDB=off", "GONOPROXY=none", "GONOSUMDB=none")
	}
	return runner.Without(runner.Environment(extra...), m.DenyEnv...), nil
}
