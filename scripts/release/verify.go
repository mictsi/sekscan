package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

type module struct {
	Path    string  `json:"Path"`
	Version string  `json:"Version,omitempty"`
	Sum     string  `json:"Sum,omitempty"`
	Main    bool    `json:"Main,omitempty"`
	Replace *module `json:"Replace,omitempty"`
}

func buildEnv(original []string, target string) []string {
	parts := strings.Split(target, "/")
	fixed := map[string]string{
		"GOOS": parts[0], "GOARCH": parts[1], "CGO_ENABLED": "0",
		"GOFLAGS": "-mod=readonly", "GOWORK": "off", "GO111MODULE": "on",
		"GOAMD64": "v1", "GOARM64": "v8.0", "GOEXPERIMENT": "",
	}
	var result []string
	for _, item := range original {
		key, _, _ := strings.Cut(item, "=")
		if _, ok := fixed[strings.ToUpper(key)]; !ok {
			result = append(result, item)
		}
	}
	for key, value := range fixed {
		result = append(result, key+"="+value)
	}
	return result
}

func buildTime(epoch string) (time.Time, error) {
	if epoch == "" {
		return time.Now().UTC().Truncate(time.Second), nil
	}
	value, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil || value < 0 || value > 4354819199 {
		return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH must be a Unix timestamp between 0 and 4354819199")
	}
	return time.Unix(value, 0).UTC(), nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func modulesUnchanged(root, mod, sum string) error {
	for name, expected := range map[string]string{"go.mod": mod, "go.sum": sum} {
		actual, err := hashFile(filepath.Join(root, name))
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("%s changed during release; no release published; resolve, review and commit modules before retrying", name)
		}
	}
	return nil
}

func parseModules(data []byte) ([]module, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var result []module
	for {
		var m module
		err := dec.Decode(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse Go module graph: %w", err)
		}
		if m.Path == "" {
			return nil, fmt.Errorf("empty module path in dependency graph")
		}
		if m.Replace != nil && m.Replace.Version == "" {
			return nil, fmt.Errorf("local module replacement for %s is not allowed in a release", m.Path)
		}
		result = append(result, m)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("empty Go module graph")
	}
	return result, nil
}

func verifyBinary(path, target string) error {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read compiled binary metadata: %w", err)
	}
	return verifyBuildInfo(info, target)
}

func verifyBuildInfo(info *debug.BuildInfo, target string) error {
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if info.Path != "sekscan/cmd/sekscan" {
		return fmt.Errorf("unexpected executable entry point %q", info.Path)
	}
	if settings["GOOS"]+"/"+settings["GOARCH"] != target {
		return fmt.Errorf("compiled executable does not match target %s", target)
	}
	if settings["CGO_ENABLED"] != "0" || strings.Contains(settings["-tags"], "offline_sqltest") {
		return fmt.Errorf("refusing to package CGo or offline_sqltest executable")
	}
	required := map[string]bool{"modernc.org/sqlite": false, "github.com/jackc/pgx/v5": false, "github.com/microsoft/go-mssqldb": false}
	for _, dep := range info.Deps {
		if dep.Replace != nil && dep.Replace.Version == "" {
			return fmt.Errorf("local replacement detected in binary: %s", dep.Path)
		}
		if _, ok := required[dep.Path]; ok {
			required[dep.Path] = true
		}
	}
	for name, present := range required {
		if !present {
			return fmt.Errorf("refusing to release executable missing production module %s", name)
		}
	}
	return nil
}
