package dbstore

import (
	"context"
	"sekscan/internal/model"
	"strings"
	"testing"
	"time"
)

func TestPortfolioLatestStateAndDailyCarryForward(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	save := func(project, id, at, branch string, n int, complete bool) {
		t.Helper()
		p, r := fixture(t)
		p.Key = project
		p.Name = "Display " + project
		r.ProjectKey = project
		r.ID = id
		r.StartedAt, _ = time.Parse(time.RFC3339, at)
		r.FinishedAt = r.StartedAt.Add(time.Second)
		r.Branch = branch
		r.Complete = complete
		r.Status = "failed"
		r.ExitCode = 1
		if !complete {
			r.Status = "incomplete"
			r.ExitCode = 2
		}
		r.Summary = model.Summary{Findings: n, Failures: n, BySeverity: map[string]int{"high": n}, ByCategory: map[string]int{"vulnerability": n}}
		if e := s.Save(ctx, p, r, nil); e != nil {
			t.Fatal(e)
		}
	}
	save("alpha", "a-old", "2026-09-01T10:00:00Z", "main", 50, true)
	save("alpha", "a-new", "2026-10-02T10:00:00Z", "main", 4, true)
	save("beta", "b-old", "2026-09-20T10:00:00Z", "main", 5, true)
	save("beta", "b-incomplete", "2026-10-03T10:00:00Z", "main", 0, false)
	save("alpha", "a-feature", "2026-10-03T11:00:00Z", "feature", 99, true)
	f := Filter{Namespace: "testing", Branch: "main", Limit: 1}
	p, e := s.portfolioAt(ctx, f, 3, now)
	if e != nil {
		t.Fatal(e)
	}
	if p.Current.Projects != 2 || p.Current.Complete != 1 || p.Current.Incomplete != 1 || p.Current.Findings != 4 || p.Current.BySeverity["high"] != 4 {
		t.Fatalf("latest-state totals %+v", p.Current)
	}
	if len(p.Points) != 3 || p.Points[0].Findings != 55 || p.Points[1].Findings != 9 || p.Points[2].Findings != 4 || p.Points[0].Stale != 2 {
		t.Fatal(p.Points)
	}
	if p.Observations != 4 {
		t.Fatal("loaded wrong branch or more than prior seeds", p.Observations)
	}
	all, e := s.portfolioAt(ctx, Filter{Namespace: "testing"}, 3, now)
	if e != nil || all.Current.Findings != 99 {
		t.Fatal(all, e)
	}
	filtered, e := s.portfolioAt(ctx, Filter{Namespace: "testing", Project: "beta"}, 3, now)
	if e != nil || filtered.Current.Projects != 1 || filtered.Current.Incomplete != 1 || filtered.Current.Findings != 0 {
		t.Fatal(filtered, e)
	}
	search, e := s.portfolioAt(ctx, Filter{Namespace: "testing", Query: "Display alpha", Branch: "main"}, 3, now)
	if e != nil || search.Current.Projects != 1 || search.Current.Findings != 4 {
		t.Fatal(search, e)
	}
	empty, e := s.portfolioAt(ctx, Filter{Namespace: "other"}, 3, now)
	if e != nil || empty.Current.Projects != 0 || len(empty.Points) != 3 {
		t.Fatal(empty, e)
	}
	end, e := s.portfolioAt(ctx, Filter{Namespace: "testing", Branch: "main", From: "2026-10-01", To: "2026-10-02"}, 30, now)
	if e != nil || end.Current.Findings != 9 || end.Days != 2 {
		t.Fatal(end, e)
	}
}
func TestPortfolioInvalidWindows(t *testing.T) {
	s := sqliteStore(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for _, days := range []int{0, -1, 91} {
		if _, e := s.portfolioAt(context.Background(), Filter{Namespace: "testing"}, days, now); e == nil {
			t.Fatal(days)
		}
	}
	for _, f := range []Filter{{Namespace: "testing", Status: "passed"}, {Namespace: "testing", From: "2025-01-01"}, {Namespace: "testing", To: "2026-10-04"}, {Namespace: "testing", From: "bad-date"}} {
		if _, e := s.portfolioAt(context.Background(), f, 30, now); e == nil {
			t.Fatal(f)
		}
	}
}
func TestPortfolioSameTimeAndMidnight(t *testing.T) {
	s := sqliteStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for i, id := range []string{"aa", "zz"} {
		p, r := fixture(t)
		r.ID = id
		r.StartedAt = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
		r.FinishedAt = r.StartedAt.Add(time.Second)
		r.Summary.Findings = i + 1
		if e := s.Save(ctx, p, r, nil); e != nil {
			t.Fatal(e)
		}
	}
	p, e := s.portfolioAt(ctx, Filter{Namespace: "testing"}, 2, now)
	if e != nil || p.Points[0].Projects != 0 || p.Current.Findings != 2 {
		t.Fatal(p, e)
	}
	if !strings.Contains(p.Note, "incomplete") {
		t.Fatal("missing interpretation limits")
	}
}
