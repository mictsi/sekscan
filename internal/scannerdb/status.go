// Package scannerdb checks native scanner caches, not the scan-history SQL database.
package scannerdb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/deps"
	"sekscan/internal/runner"
	"sekscan/internal/store"
)

type Status struct {
	Engine     string    `json:"engine"`
	Database   string    `json:"database"`
	State      string    `json:"state"`
	Path       string    `json:"path"`
	Schema     string    `json:"schema,omitempty"`
	BuiltAt    time.Time `json:"built_at,omitempty"`
	Validation string    `json:"validation"`
	Error      string    `json:"error,omitempty"`
}

func Cache(c config.Config) string { p, _ := filepath.Abs(c.Paths.Cache); return p }

func NativeConfig(c config.Config, name, fallback string) (string, error) {
	p := c.Tools[name].NativeConfig
	if p == "" {
		return fallback, nil
	}
	if _, err := store.Read(p, 4<<20); err != nil {
		return "", fmt.Errorf("cannot read %s native config", name)
	}
	return p, nil
}

func InspectGrype(ctx context.Context, c config.Config, m *deps.Manager) Status {
	s := Status{Engine: "grype", Database: "vulnerability", State: "invalid", Path: filepath.Join(Cache(c), "grype", "db"), Validation: "grype db status plus local path and age checks"}
	st := m.Inspect(ctx, "grype", c.Tools["grype"])
	if st.Error != "" {
		s.State = "tool-unavailable"
		s.Error = st.Error
		return s
	}
	temp, err := os.MkdirTemp("", "sekscan-db-status-")
	if err != nil {
		s.Error = "cannot create status work directory"
		return s
	}
	defer os.RemoveAll(temp)
	empty := filepath.Join(temp, "empty.yaml")
	if err = store.Atomic(empty, []byte("{}\n"), 0600); err != nil {
		s.Error = "cannot create status config"
		return s
	}
	native, err := NativeConfig(c, "grype", empty)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	env, err := m.Environment(true)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	result, runErr := m.Executor.Run(ctx, runner.Request{Executable: st.Path, Args: m.CommandArgs("grype", c.Tools["grype"], []string{"--config", native, "db", "status", "--output", "json"}), Dir: temp, Env: env, Timeout: 60 * time.Second, MaxOutput: 1 << 20})
	var doc struct {
		Valid    *bool           `json:"valid"`
		Built    time.Time       `json:"built"`
		Schema   json.RawMessage `json:"schemaVersion"`
		Path     string          `json:"path"`
		Location string          `json:"location"` // older Grype schemas
	}
	if json.Unmarshal(result.Stdout, &doc) != nil || doc.Valid == nil {
		s.State = "incompatible-output"
		s.Error = "cannot parse Grype database status; check the installed CLI version"
		if runErr != nil {
			s.Error = runErr.Error()
		}
		return s
	}
	if runErr != nil || !*doc.Valid {
		s.Error = "Grype reports an invalid/missing database; run sekscan db update with the same --home/--config"
		return s
	}
	if doc.Path == "" {
		doc.Path = doc.Location
	}
	if doc.Path == "" {
		s.Error = "Grype database status is missing its database path"
		return s
	}
	if err = config.WithinDirectory(s.Path, doc.Path); err != nil {
		s.Error = "Grype status points outside the selected workspace cache"
		return s
	}
	stFile, err := os.Stat(doc.Path)
	if err != nil || !stFile.Mode().IsRegular() || stFile.Size() == 0 {
		s.Error = "Grype database file is missing/empty despite status output"
		return s
	}
	s.Path = doc.Path
	s.BuiltAt = doc.Built
	if len(doc.Schema) > 0 {
		var value string
		if json.Unmarshal(doc.Schema, &value) == nil {
			s.Schema = value
		} else {
			s.Schema = string(doc.Schema)
		}
	}
	if err = checkAge(s.BuiltAt, c.MaxDBAge); err != nil {
		s.State = "stale"
		s.Error = err.Error()
		return s
	}
	s.State = "ready"
	return s
}

func InspectTrivy(c config.Config, java bool) Status {
	sub, name, dbFile := "db", "vulnerability", "trivy.db"
	if java {
		sub, name, dbFile = "java-db", "java-index", "trivy-java.db"
	}
	root := filepath.Join(Cache(c), "trivy", sub)
	s := Status{Engine: "trivy", Database: name, State: "missing", Path: root, Validation: "local metadata, age and nonempty file; scanner validates schema when it opens the DB"}
	if err := config.WithinDirectory(Cache(c), root); err != nil {
		s.State = "invalid"
		s.Error = err.Error()
		return s
	}
	meta := filepath.Join(root, "metadata.json")
	if err := config.WithinDirectory(root, meta); err != nil {
		s.State = "invalid"
		s.Error = err.Error()
		return s
	}
	b, err := store.Read(meta, 1<<20)
	if err != nil {
		s.Error = "database metadata missing/unreadable; run sekscan prepare --all --with-java --yes"
		return s
	}
	var doc struct {
		Version      int
		UpdatedAt    time.Time
		DownloadedAt time.Time
	}
	if json.Unmarshal(b, &doc) != nil || doc.Version < 1 {
		s.State = "invalid"
		s.Error = "unrecognized Trivy database metadata"
		return s
	}
	path := filepath.Join(root, dbFile)
	if err = config.WithinDirectory(root, path); err != nil {
		s.State = "invalid"
		s.Error = err.Error()
		return s
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		s.Error = "Trivy database file is missing or empty"
		return s
	}
	s.Path = path
	s.BuiltAt = doc.UpdatedAt
	s.Schema = fmt.Sprint(doc.Version)
	if err = checkAge(s.BuiltAt, c.MaxDBAge); err != nil {
		s.State = "stale"
		s.Error = err.Error()
		return s
	}
	s.State = "ready"
	return s
}

func checkAge(built time.Time, age string) error {
	max, err := time.ParseDuration(age)
	if err != nil || max <= 0 {
		return fmt.Errorf("invalid database age policy")
	}
	if built.IsZero() {
		return fmt.Errorf("database build timestamp is missing")
	}
	if built.After(time.Now().UTC().Add(5 * time.Minute)) {
		return fmt.Errorf("database timestamp is in the future; check system clock")
	}
	if time.Since(built) > max {
		return fmt.Errorf("database exceeds configured max_db_age; refresh on a connected machine")
	}
	return nil
}

func Selected(c config.Config, all bool) map[string]bool {
	out := map[string]bool{}
	for _, name := range deps.ToolNames(c, all) {
		out[name] = true
	}
	return out
}

func Statuses(ctx context.Context, c config.Config, m *deps.Manager, all, java bool) []Status {
	selected := Selected(c, all)
	out := []Status{}
	if selected["govulncheck"] {
		out = append(out, InspectGovulncheck(c))
	}
	if selected["grype"] {
		out = append(out, InspectGrype(ctx, c, m))
	}
	if selected["trivy"] || java {
		out = append(out, InspectTrivy(c, false))
	}
	if java {
		out = append(out, InspectTrivy(c, true))
	}
	return out
}
