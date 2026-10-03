package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"sekscan/internal/dbstore"
	"sekscan/internal/history"
	"sekscan/internal/report"
	"sekscan/internal/store"
)

func historyCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("history requires portfolio, projects, list, trends, compare, or export")
	}
	action := args[0]
	f := set("history "+action, errOut)
	common := addCommon(f)
	project := f.String("project", "", "exact project key filter (required for trends)")
	status := f.String("status", "", "passed, failed, or incomplete")
	branch := f.String("branch", "", "branch filter")
	kind := f.String("kind", "", "target kind filter: dir, image, sbom, etc.")
	from := f.String("from", "", "first UTC date, YYYY-MM-DD (inclusive)")
	through := f.String("to", "", "last UTC date, YYYY-MM-DD (inclusive)")
	query := f.String("q", "", "search projects, runs, or comparison evidence")
	page := f.Int("page", 1, "page number, starting at 1")
	size := f.Int("page-size", 25, "records per page, 1..200")
	limit := f.Int("limit", 0, "legacy alias for --page-size")
	offset := f.Int("offset", 0, "legacy pagination offset, 0..100000")
	days := f.Int("days", 30, "portfolio window, 1..90 UTC days")
	trendLimit := f.Int("trend-limit", 50, "latest matching runs to graph, 1..200")
	state := f.String("change", "", "comparison state filter: new, resolved, changed, unchanged, unverified")
	severity := f.String("severity", "", "comparison severity filter")
	category := f.String("category", "", "comparison category filter")
	view := f.String("view", "findings", "comparison view: findings or components")
	jsonOut := f.Bool("json", false, "print paginated JSON (trends return a bounded series)")
	dest := f.String("out", "", "export directory, or full comparison JSON filename")
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	return historyExecute(ctx, action, f.Args(), common, historyOptions{Project: *project, Status: *status, Branch: *branch, Kind: *kind, From: *from, To: *through, Query: *query, Page: *page, Size: *size, Limit: *limit, Offset: *offset, TrendLimit: *trendLimit, Days: *days, State: *state, Severity: *severity, Category: *category, View: *view, JSON: *jsonOut, Out: *dest}, out, errOut)
}

type historyOptions struct {
	Project, Status, Branch, Kind, From, To, Query, State, Severity, Category, View, Out string
	Page, Size, Limit, Offset, TrendLimit, Days                                          int
	JSON                                                                                 bool
}

func historyExecute(ctx context.Context, action string, args []string, common *common, o historyOptions, out, errOut io.Writer) error {
	if o.Limit != 0 {
		o.Size = o.Limit
	}
	if o.Size < 1 || o.Size > 200 || o.Page < 1 || o.Offset < 0 || o.Offset > 100000 {
		return fmt.Errorf("page size must be 1..200; page starts at 1; offset must be 0..100000")
	}
	if o.Offset != 0 && o.Page != 1 {
		return fmt.Errorf("use --page or --offset, not both")
	}
	if o.Offset == 0 {
		if o.Page > 100000/o.Size+1 {
			return fmt.Errorf("page is beyond 100000 records; narrow the filters")
		}
		o.Offset = (o.Page - 1) * o.Size
	}
	switch action {
	case "portfolio", "projects", "list", "trends":
		if len(args) != 0 {
			return fmt.Errorf("unexpected history arguments")
		}
	case "compare":
		if len(args) != 2 {
			return fmt.Errorf("history compare requires BASE_RUN_ID HEAD_RUN_ID")
		}
	case "export":
		if len(args) != 1 {
			return fmt.Errorf("history export requires a run ID")
		}
	default:
		return fmt.Errorf("unknown history action")
	}
	c, e := loadCommon(ctx, common)
	if e != nil {
		return e
	}
	if o.Project == "" && (action == "trends" || action == "compare") {
		o.Project = c.Project.Key
	}
	db, e := openReady(ctx, c)
	if e != nil {
		return e
	}
	defer db.Close()
	filter := dbstore.Filter{Namespace: c.Project.Namespace, Project: o.Project, Branch: o.Branch, Status: o.Status, Query: o.Query, TargetKind: o.Kind, From: o.From, To: o.To, Limit: o.Size, Offset: o.Offset}
	footer := func(total, count int) {
		fmt.Fprintf(out, "Page %d · %d records shown · %d total · page size %d\n", o.Offset/o.Size+1, count, total, o.Size)
	}
	switch action {
	case "portfolio":
		days := o.Days
		if days == 0 {
			days = 30
		}
		p, e := db.Portfolio(ctx, filter, days)
		if e != nil {
			return e
		}
		if o.JSON {
			return json.NewEncoder(out).Encode(p)
		}
		fmt.Fprintf(out, "Portfolio %s to %s UTC: %d projects, %d complete, %d incomplete, %d stale.\nFindings in complete latest assessments: %d; failed projects: %d; passed projects: %d\n%s\n", p.From, p.To, p.Current.Projects, p.Current.Complete, p.Current.Incomplete, p.Current.Stale, p.Current.Findings, p.Current.Failed, p.Current.Passed, p.Note)
		return nil
	case "projects":
		p, e := db.ProjectPage(ctx, filter)
		if e != nil {
			return e
		}
		if o.JSON {
			return json.NewEncoder(out).Encode(p)
		}
		for _, v := range p.Items {
			fmt.Fprintf(out, "%-30s %5d runs  latest=%-10s %d findings\n", v.Key, v.Runs, v.Latest.Status, v.Latest.Summary.Findings)
		}
		footer(p.Total, len(p.Items))
	case "list":
		p, e := db.ScanPage(ctx, filter)
		if e != nil {
			return e
		}
		if o.JSON {
			return json.NewEncoder(out).Encode(p)
		}
		for _, v := range p.Items {
			fmt.Fprintf(out, "%s  %-10s %-24s %s  %d findings\n", v.ID, v.Status, v.Project, v.StartedAt, v.Summary.Findings)
		}
		footer(p.Total, len(p.Items))
	case "trends":
		p, e := db.Trends(ctx, filter, o.TrendLimit)
		if e != nil {
			return e
		}
		if o.JSON {
			return json.NewEncoder(out).Encode(p)
		}
		for _, v := range p.Points {
			fmt.Fprintf(out, "%s  %-10s %d findings  %d failures  %d components  %s\n", v.StartedAt, v.Status, v.Summary.Findings, v.Summary.Failures, v.Summary.Components, v.ID)
		}
		fmt.Fprintf(out, "%d of %d matching runs; truncated=%t\n%s\n", len(p.Points), p.Total, p.Truncated, p.Note)
	case "compare":
		if e = validateChangeFilters(o.State, o.Severity, o.Category, o.Query); e != nil {
			return e
		}
		if o.View != "findings" && o.View != "components" {
			return fmt.Errorf("--view must be findings or components")
		}
		result, e := loadComparison(ctx, db, c.Project.Namespace, args[0], args[1], o.Project)
		if e != nil {
			return e
		}
		if o.Out != "" {
			b, e := json.MarshalIndent(result, "", "  ")
			if e != nil {
				return e
			}
			if e = store.Atomic(o.Out, append(b, '\n'), 0600); e != nil {
				return e
			}
			fmt.Fprintln(errOut, "Full comparison JSON written:", o.Out)
		}
		metadata := *result
		metadata.Changes = nil
		metadata.Components = nil
		if o.View == "components" {
			p := slicePage(filterComponents(result.Components, o.State, o.Query), o.Size, o.Offset)
			if o.JSON {
				return json.NewEncoder(out).Encode(map[string]any{"comparison": metadata, "page": p})
			}
			for _, v := range p.Items {
				fmt.Fprintf(out, "%-12s %s %s\n", v.State, v.Name, v.Version)
			}
			footer(p.Total, len(p.Items))
		} else {
			p := slicePage(history.FilterChanges(result.Changes, o.State, o.Severity, o.Category, o.Query), o.Size, o.Offset)
			if o.JSON {
				return json.NewEncoder(out).Encode(map[string]any{"comparison": metadata, "page": p})
			}
			fmt.Fprintf(out, "Project %s · %s → %s\nNew=%d no-longer-reported=%d changed=%d unchanged=%d unverified=%d\n", result.Project, result.Base.ID, result.Head.ID, result.Counts.New, result.Counts.Resolved, result.Counts.Changed, result.Counts.Unchanged, result.Counts.Unverified)
			for _, v := range p.Items {
				fmt.Fprintf(out, "%-12s %-8s %s %s\n", v.State, v.Severity, v.Rule, v.Package)
			}
			footer(p.Total, len(p.Items))
		}
		for _, warning := range result.Warnings {
			fmt.Fprintln(out, "Note:", warning)
		}
	case "export":
		r, e := db.Load(ctx, c.Project.Namespace, args[0])
		if e != nil {
			return e
		}
		if o.Project != "" && r.ProjectKey != o.Project {
			return fmt.Errorf("run does not belong to the selected project")
		}
		artifacts, e := db.Artifacts(ctx, c.Project.Namespace, r.ID)
		if e != nil {
			return e
		}
		if o.Out == "" {
			o.Out = "history-report"
		}
		cleanup, e := prepareOutput(o.Out)
		if e != nil {
			return e
		}
		defer cleanup()
		if e = report.Write(o.Out, r); e != nil {
			return e
		}
		for _, a := range artifacts {
			if e = store.Atomic(filepath.Join(o.Out, a.Name), a.Content, 0600); e != nil {
				return e
			}
		}
		fmt.Fprintln(out, filepath.Join(o.Out, "index.html"))
	}
	return nil
}
