package dbstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Page is the pagination envelope used by the CLI and HTTP APIs. Offsets remain
// available for existing clients; page/page_size are the preferred public interface.
type Page[T any] struct {
	Items       []T  `json:"items"`
	Total       int  `json:"total"`
	Page        int  `json:"page"`
	PageSize    int  `json:"page_size"`
	PageCount   int  `json:"page_count"`
	Offset      int  `json:"offset"`
	HasNext     bool `json:"has_next"`
	HasPrevious bool `json:"has_previous"`
}

func NewPage[T any](items []T, total, limit, offset int) Page[T] {
	if limit < 1 {
		limit = 25
	}
	if items == nil {
		items = []T{}
	}
	return Page[T]{Items: items, Total: total, Page: offset/limit + 1, PageSize: limit,
		PageCount: (total + limit - 1) / limit, Offset: offset, HasNext: offset+len(items) < total,
		HasPrevious: offset > 0}
}
func validateFilter(f Filter) (Filter, error) {
	if f.Namespace == "" || len(f.Namespace) > 128 {
		return f, fmt.Errorf("valid namespace is required")
	}
	if f.Limit == 0 {
		f.Limit = 25
	}
	if f.Limit < 1 || f.Limit > 200 {
		return f, fmt.Errorf("page size must be 1..200")
	}
	if f.Offset < 0 || f.Offset > 100000 {
		return f, fmt.Errorf("offset must be 0..100000")
	}
	if len(f.Query) > 256 || len(f.Project) > 256 || len(f.Branch) > 256 {
		return f, fmt.Errorf("search and filters are limited to 256 bytes")
	}
	switch f.Status {
	case "", "passed", "failed", "incomplete":
	default:
		return f, fmt.Errorf("invalid status filter")
	}
	switch f.TargetKind {
	case "", "dir", "rootfs", "image", "docker-archive", "oci-archive", "oci-layout", "sbom":
	default:
		return f, fmt.Errorf("invalid target kind")
	}
	for _, date := range []string{f.From, f.To} {
		if date != "" {
			if _, err := time.Parse("2006-01-02", date); err != nil {
				return f, fmt.Errorf("date filters must use YYYY-MM-DD (UTC)")
			}
		}
	}
	if f.From != "" && f.To != "" && f.From > f.To {
		return f, fmt.Errorf("from date must not be after to date")
	}
	return f, nil
}
func searchTerm(q string) string {
	return "%" + strings.NewReplacer("~", "~~", "%", "~%", "_", "~_", "[", "~[").Replace(strings.ToLower(q)) + "%"
}
func scanWhere(f Filter) (string, []any) {
	q := " FROM sekscan_scans s JOIN sekscan_projects p ON p.id=s.project_id WHERE p.namespace=?"
	args := []any{f.Namespace}
	for _, v := range []struct{ column, value string }{{"p.project_key", f.Project}, {"s.branch", f.Branch}, {"s.status", f.Status}, {"s.target_kind", f.TargetKind}} {
		if v.value != "" {
			q += " AND " + v.column + "=?"
			args = append(args, v.value)
		}
	}
	if f.From != "" {
		t, _ := time.Parse("2006-01-02", f.From)
		q += " AND s.started_at>=?"
		args = append(args, t.Format(stamp))
	}
	if f.To != "" {
		t, _ := time.Parse("2006-01-02", f.To)
		q += " AND s.started_at<?"
		args = append(args, t.AddDate(0, 0, 1).Format(stamp))
	}
	if f.Query != "" {
		q += " AND (LOWER(p.project_key) LIKE ? ESCAPE '~' OR LOWER(s.revision) LIKE ? ESCAPE '~' OR LOWER(s.target_value) LIKE ? ESCAPE '~')"
		v := searchTerm(f.Query)
		args = append(args, v, v, v)
	}
	return q, args
}
func (s *Store) paginated(q string, args []any, limit, offset int) (string, []any) {
	if s.dialect == "mssql" {
		q += " OFFSET ? ROWS FETCH NEXT ? ROWS ONLY"
		args = append(args, offset, limit)
	} else {
		q += " LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	}
	return s.bind(q), args
}
func (s *Store) CountScans(ctx context.Context, f Filter) (int, error) {
	f, err := validateFilter(f)
	if err != nil {
		return 0, err
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	where, args := scanWhere(f)
	var total int
	if err = s.db.QueryRowContext(ctx, s.bind("SELECT COUNT(*)"+where), args...).Scan(&total); err != nil {
		return 0, dbError("count scans")
	}
	return total, nil
}
func (s *Store) List(ctx context.Context, f Filter) ([]ScanEntry, error) {
	f, err := validateFilter(f)
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	where, args := scanWhere(f)
	q, args := s.paginated("SELECT s.id,p.namespace,p.project_key,s.started_at,s.status,s.revision,s.branch,s.summary_json,s.target_kind,s.target_value,s.finished_at,s.complete"+where+" ORDER BY s.started_at DESC,s.id DESC", args, f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, dbError("list scans")
	}
	defer rows.Close()
	items := []ScanEntry{}
	for rows.Next() {
		var v ScanEntry
		var raw, finish string
		var complete int
		if err = rows.Scan(&v.ID, &v.Namespace, &v.Project, &v.StartedAt, &v.Status, &v.Revision, &v.Branch, &raw, &v.TargetKind, &v.TargetValue, &finish, &complete); err != nil {
			return nil, dbError("read scan list")
		}
		if err = json.Unmarshal([]byte(raw), &v.Summary); err != nil {
			return nil, fmt.Errorf("invalid stored summary")
		}
		start, e := time.Parse(stamp, v.StartedAt)
		end, e2 := time.Parse(stamp, finish)
		if e != nil || e2 != nil {
			return nil, fmt.Errorf("invalid stored scan time")
		}
		v.Complete = complete == 1
		v.DurationMS = end.Sub(start).Milliseconds()
		items = append(items, v)
	}
	if rows.Err() != nil {
		return nil, dbError("finish scan list")
	}
	return items, nil
}
func (s *Store) ScanPage(ctx context.Context, f Filter) (Page[ScanEntry], error) {
	f, err := validateFilter(f)
	if err != nil {
		return Page[ScanEntry]{}, err
	}
	total, err := s.CountScans(ctx, f)
	if err != nil {
		return Page[ScanEntry]{}, err
	}
	items, err := s.List(ctx, f)
	if err != nil {
		return Page[ScanEntry]{}, err
	}
	return NewPage(items, total, f.Limit, f.Offset), nil
}

type ProjectEntry struct {
	ID         string    `json:"id"`
	Namespace  string    `json:"namespace"`
	Key        string    `json:"key"`
	Name       string    `json:"name"`
	Repository string    `json:"repository"`
	Runs       int       `json:"runs"`
	Passed     int       `json:"passed"`
	Failed     int       `json:"failed"`
	Incomplete int       `json:"incomplete"`
	Latest     ScanEntry `json:"latest"`
}

func projectWhere(namespace, q string) (string, []any) {
	where := " WHERE p.namespace=?"
	args := []any{namespace}
	if q != "" {
		where += " AND (LOWER(p.project_key) LIKE ? ESCAPE '~' OR LOWER(p.name) LIKE ? ESCAPE '~')"
		v := searchTerm(q)
		args = append(args, v, v)
	}
	return where, args
}
func (s *Store) ProjectPage(ctx context.Context, f Filter) (Page[ProjectEntry], error) {
	f, err := validateFilter(f)
	if err != nil {
		return Page[ProjectEntry]{}, err
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	where, args := projectWhere(f.Namespace, f.Query)
	if f.Project != "" {
		where += " AND p.project_key=?"
		args = append(args, f.Project)
	}
	var total int
	if err = s.db.QueryRowContext(ctx, s.bind("SELECT COUNT(*) FROM sekscan_projects p"+where+" AND EXISTS (SELECT 1 FROM sekscan_scans s WHERE s.project_id=p.id)"), args...).Scan(&total); err != nil {
		return Page[ProjectEntry]{}, dbError("count projects")
	}
	// Windows and counts are restricted to the selected namespace. Only one summary
	// per project is read, never full report_json blobs or all findings.
	q := `WITH runs AS (
      SELECT s.project_id,s.id,s.started_at,s.status,s.revision,s.branch,s.summary_json,s.target_kind,s.target_value,
        ROW_NUMBER() OVER (PARTITION BY s.project_id ORDER BY s.started_at DESC,s.id DESC) AS rn,
        COUNT(*) OVER (PARTITION BY s.project_id) AS run_count,
        SUM(CASE WHEN s.status='passed' THEN 1 ELSE 0 END) OVER (PARTITION BY s.project_id) AS passed,
        SUM(CASE WHEN s.status='failed' THEN 1 ELSE 0 END) OVER (PARTITION BY s.project_id) AS failed,
        SUM(CASE WHEN s.status='incomplete' THEN 1 ELSE 0 END) OVER (PARTITION BY s.project_id) AS incomplete
      FROM sekscan_scans s JOIN sekscan_projects p ON s.project_id=p.id` + where + `)
    SELECT p.id,p.namespace,p.project_key,p.name,p.repository_uri,r.run_count,r.passed,r.failed,r.incomplete,
      r.id,r.started_at,r.status,r.revision,r.branch,r.summary_json,r.target_kind,r.target_value
    FROM sekscan_projects p JOIN runs r ON r.project_id=p.id AND r.rn=1
    ORDER BY r.started_at DESC,p.id DESC`
	q, args = s.paginated(q, args, f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return Page[ProjectEntry]{}, dbError("list projects")
	}
	defer rows.Close()
	items := []ProjectEntry{}
	for rows.Next() {
		var v ProjectEntry
		var raw string
		if err = rows.Scan(&v.ID, &v.Namespace, &v.Key, &v.Name, &v.Repository, &v.Runs, &v.Passed, &v.Failed, &v.Incomplete, &v.Latest.ID, &v.Latest.StartedAt, &v.Latest.Status, &v.Latest.Revision, &v.Latest.Branch, &raw, &v.Latest.TargetKind, &v.Latest.TargetValue); err != nil {
			return Page[ProjectEntry]{}, dbError("read project list")
		}
		if err = json.Unmarshal([]byte(raw), &v.Latest.Summary); err != nil {
			return Page[ProjectEntry]{}, fmt.Errorf("invalid project summary")
		}
		v.Latest.Project = v.Key
		v.Latest.Namespace = v.Namespace
		v.Latest.Complete = v.Latest.Status != "incomplete"
		items = append(items, v)
	}
	if rows.Err() != nil {
		return Page[ProjectEntry]{}, dbError("finish project list")
	}
	return NewPage(items, total, f.Limit, f.Offset), nil
}

type TrendResult struct {
	Points    []ScanEntry `json:"points"`
	Total     int         `json:"total_matching_runs"`
	Limit     int         `json:"limit"`
	Truncated bool        `json:"truncated"`
	Note      string      `json:"note"`
}

func (s *Store) Trends(ctx context.Context, f Filter, limit int) (TrendResult, error) {
	if f.Project == "" {
		return TrendResult{}, fmt.Errorf("trends require a project")
	}
	f.Limit = limit
	f.Offset = 0
	page, err := s.ScanPage(ctx, f)
	if err != nil {
		return TrendResult{}, err
	}
	items := page.Items
	// The graph is chronological even though the run list is newest-first.
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	return TrendResult{Points: items, Total: page.Total, Limit: limit, Truncated: page.Total > limit,
		Note: "Recorded counts, not proof of remediation. Incomplete runs are marked; scanner, configuration, target, and advisory-database changes may alter counts."}, nil
}
