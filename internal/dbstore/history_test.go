package dbstore

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestProjectsRunsAndTrendsPagination(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t)
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	for project := 0; project < 3; project++ {
		for i := 0; i < 7; i++ {
			p, r := fixture(t)
			p.Key = fmt.Sprintf("service-%d", project)
			p.Name = p.Key
			r.ProjectKey = p.Key
			r.ID = fmt.Sprintf("scan-%d-%02d", project, i)
			r.StartedAt = start.AddDate(0, 0, i)
			r.FinishedAt = r.StartedAt.Add(time.Second)
			r.Branch = "main"
			if i == 5 {
				r.Branch = "feature"
			}
			if e := s.Save(ctx, p, r, nil); e != nil {
				t.Fatal(e)
			}
		}
	}
	first, e := s.ProjectPage(ctx, Filter{Namespace: "testing", Limit: 2})
	if e != nil || first.Total != 3 || len(first.Items) != 2 || !first.HasNext {
		t.Fatal(first, e)
	}
	second, e := s.ProjectPage(ctx, Filter{Namespace: "testing", Limit: 2, Offset: 2})
	if e != nil || len(second.Items) != 1 || second.HasNext || !second.HasPrevious {
		t.Fatal(second, e)
	}
	if first.Items[0].Key == second.Items[0].Key || first.Items[0].Runs != 7 || !strings.HasSuffix(first.Items[0].Latest.ID, "06") {
		t.Fatal("project order/count", first, second)
	}
	exact, e := s.ProjectPage(ctx, Filter{Namespace: "testing", Project: "service-0", Limit: 10})
	if e != nil || exact.Total != 1 || len(exact.Items) != 1 || exact.Items[0].Key != "service-0" {
		t.Fatal("exact project filter", exact, e)
	}
	page, e := s.ScanPage(ctx, Filter{Namespace: "testing", Project: "service-0", Limit: 3, Offset: 3})
	if e != nil || page.Total != 7 || len(page.Items) != 3 || page.Items[0].ID != "scan-0-03" || !page.HasNext {
		t.Fatal(page, e)
	}
	last, e := s.ScanPage(ctx, Filter{Namespace: "testing", Project: "service-0", Limit: 3, Offset: 6})
	if e != nil || len(last.Items) != 1 || last.HasNext {
		t.Fatal(last, e)
	}
	out, e := s.ScanPage(ctx, Filter{Namespace: "testing", Project: "service-0", Limit: 3, Offset: 9})
	if e != nil || len(out.Items) != 0 || out.Total != 7 {
		t.Fatal(out, e)
	}
	trend, e := s.Trends(ctx, Filter{Namespace: "testing", Project: "service-0"}, 3)
	if e != nil || !trend.Truncated || trend.Total != 7 || len(trend.Points) != 3 || trend.Points[0].ID != "scan-0-04" {
		t.Fatal(trend, e)
	}
	filtered, e := s.ScanPage(ctx, Filter{Namespace: "testing", Project: "service-0", Branch: "main", From: "2026-09-05", To: "2026-09-07", Limit: 25})
	if e != nil || filtered.Total != 2 {
		t.Fatal(filtered, e)
	}
	empty, e := s.ProjectPage(ctx, Filter{Namespace: "private", Limit: 10})
	if e != nil || empty.Total != 0 || len(empty.Items) != 0 {
		t.Fatal("namespace leakage", empty, e)
	}
	wildcard, e := s.ProjectPage(ctx, Filter{Namespace: "testing", Query: "%", Limit: 10})
	if e != nil || wildcard.Total != 0 {
		t.Fatal("wildcard search", wildcard, e)
	}
}
func TestHistoryPaginationValidation(t *testing.T) {
	for _, f := range []Filter{{Namespace: "n", Limit: -1}, {Namespace: "n", Limit: 201}, {Namespace: "n", Offset: -1}, {Namespace: "n", Offset: 100001}, {Namespace: "n", Status: "nonsense"}, {Namespace: "n", From: "2026-99-12"}, {Namespace: "n", From: "2026-10-02", To: "2026-09-01"}, {Namespace: "n", TargetKind: "../"}, {Namespace: "n", Query: strings.Repeat("x", 257)}} {
		if _, e := validateFilter(f); e == nil {
			t.Fatal("invalid filter accepted", f)
		}
	}
}
func TestHistoryPagingSQLDialects(t *testing.T) {
	for _, d := range []string{"sqlite", "postgres", "mssql"} {
		s := Store{dialect: d}
		q, args := s.paginated("SELECT id FROM t WHERE ns=? ORDER BY id", []any{"n"}, 25, 50)
		if d == "mssql" {
			if !strings.Contains(q, "OFFSET @p2 ROWS FETCH NEXT @p3 ROWS ONLY") || args[1] != 50 || args[2] != 25 {
				t.Fatal(q, args)
			}
		} else {
			if !strings.Contains(q, "LIMIT") || args[1] != 25 || args[2] != 50 {
				t.Fatal(q, args)
			}
		}
	}
}
