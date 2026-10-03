// Package dbstore persists immutable scan snapshots using portable, parameterized SQL.
package dbstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sekscan/internal/config"
	"sekscan/internal/model"
)

type Store struct {
	db       *sql.DB
	dialect  string
	settings config.Storage
}
type Artifact struct {
	Name, MediaType string
	Content         []byte
}
type Filter struct {
	Namespace, Project, Branch, Status, Query string
	TargetKind, From, To                      string
	Limit, Offset                             int
}
type ScanEntry struct {
	ID          string        `json:"id"`
	Namespace   string        `json:"namespace"`
	Project     string        `json:"project"`
	StartedAt   string        `json:"started_at"`
	Status      string        `json:"status"`
	Revision    string        `json:"revision"`
	Branch      string        `json:"branch"`
	Summary     model.Summary `json:"summary"`
	TargetKind  string        `json:"target_kind"`
	TargetValue string        `json:"target_value"`
	Complete    bool          `json:"complete"`
	DurationMS  int64         `json:"duration_ms"`
}

var ErrNotFound = errors.New("scan not found in the selected namespace")
var ErrConflict = errors.New("scan ID already exists with a different snapshot; immutable scans cannot be overwritten")

const stamp = "2006-01-02T15:04:05.000000Z"

func Dialect(name string) (string, error) {
	switch name {
	case "sqlite":
		return "sqlite", nil
	case "postgres", "postgresql":
		return "postgres", nil
	case "mssql", "sqlserver":
		return "mssql", nil
	}
	return "", fmt.Errorf("unsupported database driver")
}

// Open never creates a remote database and never interpolates credentials into an error.
func Open(ctx context.Context, c config.Storage) (*Store, error) {
	d, e := Dialect(c.Driver)
	if e != nil {
		return nil, e
	}
	var driver, dsn string
	switch d {
	case "sqlite":
		if c.Path == "" {
			return nil, fmt.Errorf("SQLite path is empty")
		}
		absolute, e := filepath.Abs(c.Path)
		if e != nil {
			return nil, e
		}
		if e = os.MkdirAll(filepath.Dir(absolute), 0700); e != nil {
			return nil, e
		}
		st, err := os.Lstat(absolute)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("cannot inspect SQLite database file")
		}
		if err == nil && (!st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0) {
			return nil, fmt.Errorf("SQLite database must be a regular non-symlink file")
		}
		// Do not open/close an existing SQLite inode outside its driver: on POSIX that
		// can release locks held by another connection in this process.
		if os.IsNotExist(err) {
			f, createErr := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if createErr != nil && !os.IsExist(createErr) {
				return nil, fmt.Errorf("cannot create SQLite database file")
			}
			if createErr == nil {
				if closeErr := f.Close(); closeErr != nil {
					return nil, fmt.Errorf("cannot close new database file")
				}
			}
			if current, statErr := os.Lstat(absolute); statErr != nil || !current.Mode().IsRegular() {
				return nil, fmt.Errorf("SQLite database must be a regular file")
			}
		}
		// _pragma settings are applied on every connection by modernc.org/sqlite.
		uriPath := filepath.ToSlash(absolute)
		if len(uriPath) > 1 && uriPath[1] == ':' {
			uriPath = "/" + uriPath
		} // Windows drive is a path, not a URI authority.
		u := url.URL{Scheme: "file", Path: uriPath}
		q := url.Values{}
		q.Add("_pragma", "foreign_keys(1)")
		q.Add("_pragma", "busy_timeout(10000)")
		q.Add("_pragma", "journal_mode(WAL)")
		q.Set("_txlock", "immediate")
		u.RawQuery = q.Encode()
		driver, dsn = "sqlite", u.String()
	case "postgres", "mssql":
		raw := os.Getenv(c.DSNEnv)
		if raw == "" {
			return nil, fmt.Errorf("database connection environment variable is not set")
		}
		dsn, e = ValidateDSN(d, raw, c.AllowInsecureTLS)
		if e != nil {
			return nil, e
		}
		driver = "pgx"
		if d == "mssql" {
			driver = "sqlserver"
		}
	}
	db, e := sql.Open(driver, dsn)
	if e != nil {
		return nil, fmt.Errorf("database driver initialization failed; check driver availability and connection settings")
	}
	max := c.MaxOpenConns
	if max < 1 {
		max = 4
	}
	if d == "sqlite" {
		max = 1
	}
	db.SetMaxOpenConns(max)
	db.SetMaxIdleConns(max)
	db.SetConnMaxLifetime(30 * time.Minute)
	timeout, e := time.ParseDuration(c.Timeout)
	if e != nil || timeout <= 0 {
		timeout = 30 * time.Second
	}
	ping, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if e = db.PingContext(ping); e != nil {
		db.Close()
		return nil, fmt.Errorf("database connection failed; check credentials, TLS, reachability, and server logs")
	}
	return &Store{db: db, dialect: d, settings: c}, nil
}

// ValidateDSN accepts URL-style DSNs only. TLS verification cannot silently downgrade.
func ValidateDSN(d, raw string, insecure bool) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.Fragment != "" {
		return "", fmt.Errorf("database DSN must be a valid connection URL")
	}
	if (d == "postgres" && u.Scheme != "postgres" && u.Scheme != "postgresql") || (d == "mssql" && u.Scheme != "sqlserver") {
		return "", fmt.Errorf("database DSN scheme does not match driver")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", fmt.Errorf("invalid database connection options")
	}
	canonical := url.Values{}
	for key, values := range q {
		k := strings.ToLower(key)
		if _, ok := canonical[k]; ok || len(values) != 1 {
			return "", fmt.Errorf("duplicate database connection option")
		}
		canonical[k] = values
	}
	q = canonical
	if d == "postgres" {
		if !insecure && q.Get("sslmode") != "" && q.Get("sslmode") != "verify-full" {
			return "", fmt.Errorf("PostgreSQL requires sslmode=verify-full; insecure development connections require allow_insecure_tls")
		}
		if q.Get("sslmode") == "" {
			q.Set("sslmode", "verify-full")
		}
		// An environment-supplied DSN must not override process-level authentication files.
		if q.Get("service") != "" {
			return "", fmt.Errorf("PostgreSQL service indirection is not supported; use an explicit URL")
		}
		q.Set("application_name", "sekscan")
	} else {
		encrypt := strings.ToLower(q.Get("encrypt"))
		trust := strings.ToLower(q.Get("trustservercertificate"))
		if !insecure {
			if encrypt != "" && encrypt != "true" && encrypt != "mandatory" && encrypt != "strict" && encrypt != "yes" && encrypt != "1" && encrypt != "t" {
				return "", fmt.Errorf("SQL Server encryption is required")
			}
			if trust != "" && trust != "false" && trust != "0" && trust != "no" && trust != "f" {
				return "", fmt.Errorf("SQL Server certificate verification is required")
			}
			q.Set("trustservercertificate", "false")
			if encrypt == "" {
				q.Set("encrypt", "true")
			}
		}
		// Driver trace logging can include query parameters and must remain disabled.
		q.Set("log", "0")
		q.Set("app name", "sekscan")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	d, e := time.ParseDuration(s.settings.Timeout)
	if e != nil || d <= 0 {
		d = 30 * time.Second
	}
	return context.WithTimeout(ctx, d)
}
func (s *Store) bind(q string) string {
	if s.dialect == "sqlite" {
		return q
	}
	i := 0
	return replacePlaceholders(q, func() string {
		i++
		if s.dialect == "postgres" {
			return fmt.Sprintf("$%d", i)
		}
		return fmt.Sprintf("@p%d", i)
	})
}
func replacePlaceholders(q string, next func() string) string {
	var b strings.Builder
	for _, c := range q {
		if c == '?' {
			b.WriteString(next())
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func encode(v any) string    { b, _ := json.Marshal(v); return string(b) }
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func validateSnapshot(r *model.Report, p config.Project, artifacts []Artifact, maxMB int) error {
	if r == nil || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(r.ID) {
		return fmt.Errorf("invalid report ID")
	}
	if r.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("unsupported report schema version")
	}
	if p.Namespace == "" || p.Key == "" || len(p.Namespace) > 128 || len(p.Key) > 256 || len(p.Name) > 256 {
		return fmt.Errorf("project namespace and stable key are required within schema limits")
	}
	if r.Namespace != p.Namespace || r.ProjectKey != p.Key {
		return fmt.Errorf("report project identity differs from destination")
	}
	if r.StartedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) {
		return fmt.Errorf("invalid scan timestamps")
	}
	if len(r.Revision) > 256 || len(r.Branch) > 256 || len(r.AppVersion) > 128 || len(r.ConfigHash) > 64 {
		return fmt.Errorf("report metadata exceeds schema limits")
	}
	if len(r.Components) > 500000 || len(r.Findings)+len(r.Resolved) > 500000 || len(r.Engines) > 1000 {
		return fmt.Errorf("snapshot exceeds record limits")
	}
	if (r.Status == "passed" && (!r.Complete || r.ExitCode != 0)) || (r.Status == "failed" && (!r.Complete || r.ExitCode != 1)) || (r.Status == "incomplete" && (r.Complete || r.ExitCode != 2)) {
		return fmt.Errorf("inconsistent report status")
	}
	switch r.Status {
	case "passed", "failed", "incomplete":
	default:
		return fmt.Errorf("invalid report status")
	}
	ids := map[string]bool{}
	for _, c := range r.Components {
		if c.ID == "" || len(c.ID) > 64 || ids[c.ID] {
			return fmt.Errorf("component identifiers must be unique within a scan")
		}
		ids[c.ID] = true
		if len(c.Scope) > 32 || len(c.Ecosystem) > 64 {
			return fmt.Errorf("component metadata exceeds schema limits")
		}
	}
	for _, f := range append(append([]model.Finding{}, r.Findings...), r.Resolved...) {
		if f.Fingerprint == "" || len(f.Fingerprint) > 64 || len(f.ComponentID) > 64 || len(f.Category) > 32 || len(f.Scope) > 32 || len(f.Severity) > 16 || len(f.Decision) > 16 || len(f.Baseline) > 16 {
			return fmt.Errorf("invalid finding metadata")
		}
	}
	for _, e := range r.Engines {
		if e.Name == "" || len(e.Name) > 64 || len(e.Version) > 128 || len(e.Status) > 16 || !json.Valid([]byte(encode(e))) {
			return fmt.Errorf("invalid engine metadata")
		}
	}
	names := map[string]bool{}
	total := 0
	if maxMB < 1 {
		maxMB = 64
	}
	for _, a := range artifacts {
		if !AllowedArtifact(a.Name) || names[a.Name] {
			return fmt.Errorf("invalid or duplicate artifact name")
		}
		names[a.Name] = true
		if len(a.Content) > maxMB<<20 {
			return fmt.Errorf("artifact exceeds configured size limit")
		}
		total += len(a.Content)
		if !json.Valid(a.Content) {
			return fmt.Errorf("SBOM artifact is not valid JSON")
		}
	}
	if total > 256<<20 {
		return fmt.Errorf("artifact set exceeds 256 MiB")
	}
	return nil
}
func AllowedArtifact(name string) bool {
	return name == "sbom.syft.json" || name == "sbom.cdx.json" || name == "sbom.spdx.json"
}

// Save inserts an entire immutable snapshot atomically. Exact retries are idempotent.
func (s *Store) Save(ctx context.Context, p config.Project, r *model.Report, artifacts []Artifact) error {
	if e := validateSnapshot(r, p, artifacts, s.settings.MaxArtifactMB); e != nil {
		return e
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > 64<<20 {
		return fmt.Errorf("report is invalid or exceeds 64 MiB")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return dbError("begin write")
	}
	defer tx.Rollback()
	projectID := model.Hash(p.Namespace, p.Key)
	if e = s.lock(ctx, tx, "project:"+projectID); e != nil {
		return e
	}
	var old, oldProject string
	e = tx.QueryRowContext(ctx, s.bind("SELECT payload_sha256,project_id FROM sekscan_scans WHERE id=?"), r.ID).Scan(&old, &oldProject)
	if e == nil {
		if old != digest(b) || oldProject != projectID {
			return ErrConflict
		}
		// Artifact content is part of the immutable snapshot, not an updatable attachment.
		rows, err := tx.QueryContext(ctx, s.bind("SELECT name,sha256 FROM sekscan_artifacts WHERE scan_id=?"), r.ID)
		if err != nil {
			return dbError("read existing artifacts")
		}
		stored := map[string]string{}
		for rows.Next() {
			var name, hash string
			if err = rows.Scan(&name, &hash); err != nil {
				rows.Close()
				return dbError("read artifact identity")
			}
			stored[name] = hash
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return dbError("read artifact identity")
		}
		if len(stored) != len(artifacts) {
			return ErrConflict
		}
		for _, a := range artifacts {
			if stored[a.Name] != digest(a.Content) {
				return ErrConflict
			}
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return dbError("read existing snapshot; run storage migrate if schema is missing")
	}
	var exists string
	e = tx.QueryRowContext(ctx, s.bind("SELECT id FROM sekscan_projects WHERE id=?"), projectID).Scan(&exists)
	if errors.Is(e, sql.ErrNoRows) {
		name := p.Name
		if name == "" {
			name = p.Key
		}
		_, e = tx.ExecContext(ctx, s.bind("INSERT INTO sekscan_projects(id,namespace,project_key,name,repository_uri,created_at) VALUES(?,?,?,?,?,?)"), projectID, p.Namespace, p.Key, name, p.Repository, time.Now().UTC().Format(stamp))
	}
	if e != nil {
		return dbError("write project")
	}
	_, e = tx.ExecContext(ctx, s.bind(`INSERT INTO sekscan_scans(id,project_id,started_at,finished_at,target_kind,target_value,target_identity,revision,branch,app_version,config_hash,status,complete,exit_code,summary_json,report_json,payload_sha256,stored_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), r.ID, projectID, r.StartedAt.UTC().Format(stamp), r.FinishedAt.UTC().Format(stamp), r.Target.Kind, r.Target.Value, r.Target.Identity, r.Revision, r.Branch, r.AppVersion, r.ConfigHash, r.Status, boolInt(r.Complete), r.ExitCode, encode(r.Summary), string(b), digest(b), time.Now().UTC().Format(stamp))
	if e != nil {
		return dbError("write scan")
	}
	for i, v := range r.Engines {
		_, e = tx.ExecContext(ctx, s.bind("INSERT INTO sekscan_engine_runs(scan_id,ordinal,name,version,status,required,duration_ms,result_json) VALUES(?,?,?,?,?,?,?,?)"), r.ID, i, v.Name, v.Version, v.Status, boolInt(v.Required), v.DurationMS, encode(v))
		if e != nil {
			return dbError("write engine run")
		}
	}
	for _, v := range r.Components {
		_, e = tx.ExecContext(ctx, s.bind("INSERT INTO sekscan_components(scan_id,component_id,name,version,purl,ecosystem,scope,component_json) VALUES(?,?,?,?,?,?,?,?)"), r.ID, v.ID, v.Name, v.Version, v.PURL, v.Ecosystem, v.Scope, encode(v))
		if e != nil {
			return dbError("write component")
		}
	}
	all := append(append([]model.Finding{}, r.Findings...), r.Resolved...)
	for i, v := range all {
		var component any
		if v.ComponentID != "" {
			component = v.ComponentID
		}
		_, e = tx.ExecContext(ctx, s.bind("INSERT INTO sekscan_findings(scan_id,ordinal,fingerprint,component_id,category,rule_id,severity,scope,decision,baseline_state,resolved,finding_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"), r.ID, i, v.Fingerprint, component, v.Category, v.RuleID, v.Severity, v.Scope, v.Decision, v.Baseline, boolInt(i >= len(r.Findings)), encode(v))
		if e != nil {
			return dbError("write finding")
		}
	}
	for _, a := range artifacts {
		_, e = tx.ExecContext(ctx, s.bind("INSERT INTO sekscan_artifacts(scan_id,name,media_type,sha256,size_bytes,content) VALUES(?,?,?,?,?,?)"), r.ID, a.Name, "application/json", digest(a.Content), len(a.Content), a.Content)
		if e != nil {
			return dbError("write artifact")
		}
	}
	if e = tx.Commit(); e != nil {
		return dbError("commit snapshot")
	}
	return nil
}
func dbError(operation string) error {
	return fmt.Errorf("database could not %s; details withheld because driver errors may contain sensitive data", operation)
}

func (s *Store) Load(ctx context.Context, namespace, id string) (*model.Report, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var raw, hash string
	e := s.db.QueryRowContext(ctx, s.bind("SELECT s.report_json,s.payload_sha256 FROM sekscan_scans s JOIN sekscan_projects p ON p.id=s.project_id WHERE s.id=? AND p.namespace=?"), id, namespace).Scan(&raw, &hash)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, dbError("load scan")
	}
	if len(raw) > 64<<20 || digest([]byte(raw)) != hash {
		return nil, fmt.Errorf("stored report integrity check failed")
	}
	var r model.Report
	if e = json.Unmarshal([]byte(raw), &r); e != nil {
		return nil, fmt.Errorf("invalid stored report")
	}
	return &r, nil
}
func (s *Store) Artifacts(ctx context.Context, namespace, id string) ([]Artifact, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	rows, e := s.db.QueryContext(ctx, s.bind("SELECT a.name,a.media_type,a.content,a.sha256 FROM sekscan_artifacts a JOIN sekscan_scans s ON s.id=a.scan_id JOIN sekscan_projects p ON p.id=s.project_id WHERE s.id=? AND p.namespace=? ORDER BY a.name"), id, namespace)
	if e != nil {
		return nil, dbError("load artifacts")
	}
	defer rows.Close()
	out := []Artifact{}
	total := 0
	for rows.Next() {
		var a Artifact
		var hash string
		if e = rows.Scan(&a.Name, &a.MediaType, &a.Content, &hash); e != nil {
			return nil, dbError("read artifact")
		}
		total += len(a.Content)
		if total > 256<<20 || !AllowedArtifact(a.Name) || digest(a.Content) != hash {
			return nil, fmt.Errorf("artifact integrity or size check failed")
		}
		out = append(out, a)
	}
	if rows.Err() != nil {
		return nil, dbError("finish artifacts")
	}
	return out, nil
}
