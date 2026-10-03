package dbstore

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"sekscan/internal/model"
)

// Portfolio uses latest matching state per project, never the sum of repeated
// assessments. Counts intentionally exclude incomplete latest snapshots.
type PortfolioPoint struct {
	Date       string         `json:"date"`
	Projects   int            `json:"projects"`
	Complete   int            `json:"complete_projects"`
	Passed     int            `json:"passed"`
	Failed     int            `json:"failed"`
	Incomplete int            `json:"incomplete"`
	Stale      int            `json:"stale_projects"`
	Findings   int            `json:"findings"`
	Failures   int            `json:"failures"`
	Reviews    int            `json:"reviews"`
	Components int            `json:"components"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
}
type PortfolioResult struct {
	Current          PortfolioPoint   `json:"current"`
	Points           []PortfolioPoint `json:"points"`
	LatestObservedAt string           `json:"latest_observed_at,omitempty"`
	From             string           `json:"from"`
	To               string           `json:"to"`
	Days             int              `json:"days"`
	StaleAfterDays   int              `json:"stale_after_days"`
	Observations     int              `json:"observations"`
	Note             string           `json:"note"`
}

const portfolioLimit = 50000

func (s *Store) Portfolio(ctx context.Context, filter Filter, days int) (PortfolioResult, error) {
	return s.portfolioAt(ctx, filter, days, time.Now().UTC())
}
func (s *Store) portfolioAt(ctx context.Context, f Filter, days int, now time.Time) (PortfolioResult, error) {
	f, err := validateFilter(f)
	if err != nil {
		return PortfolioResult{}, err
	}
	if days < 1 || days > 90 {
		return PortfolioResult{}, fmt.Errorf("portfolio days must be 1..90")
	}
	// Status filtering here could hide a project's most recent failed run behind
	// an older pass. Filter status on run lists instead, not aggregate state.
	if f.Status != "" {
		return PortfolioResult{}, fmt.Errorf("portfolio status filters are not supported; filter the run list instead")
	}
	last := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if f.To != "" {
		last, _ = time.Parse("2006-01-02", f.To)
		if last.After(now) {
			return PortfolioResult{}, fmt.Errorf("portfolio end date is in the future")
		}
	}
	start := last.AddDate(0, 0, -days+1)
	if f.From != "" {
		start, _ = time.Parse("2006-01-02", f.From)
		days = int(last.Sub(start).Hours()/24) + 1
		if days < 1 || days > 90 {
			return PortfolioResult{}, fmt.Errorf("portfolio date window must be 1..90 days")
		}
	}
	result := PortfolioResult{From: start.Format("2006-01-02"), To: last.Format("2006-01-02"), Days: days, StaleAfterDays: 7, Points: []PortfolioPoint{}, Note: "Latest matching run per project at each UTC day end; carried forward until the next scan. Finding/component totals exclude incomplete latest runs; they are not zero findings. Different scopes, scanner versions, policy and advisory databases can change counts. Snapshots older than 7 days are marked stale. No cross-project finding deduplication is implied."}
	// Seed each project's latest state before the graph window, then stream only
	// events inside it. No full report blobs or per-finding rows are loaded.
	end := last.AddDate(0, 0, 1)
	if end.After(now) {
		end = now
	}
	f.From, f.To = "", ""
	f.Offset = 0
	search := f.Query
	f.Query = ""
	where, args := scanWhere(f)
	if search != "" {
		where += " AND (LOWER(p.project_key) LIKE ? ESCAPE '~' OR LOWER(p.name) LIKE ? ESCAPE '~')"
		args = append(args, searchTerm(search), searchTerm(search))
	}
	where += " AND s.started_at<=?"
	args = append(args, end.Format(stamp))
	q := `WITH filtered AS (
 SELECT p.project_key,s.id,s.started_at,s.status,s.complete,s.summary_json` + where + `),
 prior AS (SELECT *,ROW_NUMBER() OVER (PARTITION BY project_key ORDER BY started_at DESC,id DESC) AS rn
 FROM filtered WHERE started_at<?)
 SELECT project_key,id,started_at,status,complete,summary_json FROM prior WHERE rn=1
 UNION ALL
 SELECT project_key,id,started_at,status,complete,summary_json FROM filtered WHERE started_at>=?
 ORDER BY started_at ASC,id ASC`
	args = append(args, start.Format(stamp), start.Format(stamp))
	// SQL-side bounds are applied around the union for both supported SQL syntaxes.
	q, args = s.paginated(q, args, portfolioLimit+1, 0)
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return result, dbError("load portfolio trends")
	}
	defer rows.Close()
	type observation struct {
		Project, ID, Started, Status string
		Complete                     bool
		Summary                      model.Summary
	}
	obs := []observation{}
	for rows.Next() {
		var o observation
		var complete int
		var raw string
		if err = rows.Scan(&o.Project, &o.ID, &o.Started, &o.Status, &complete, &raw); err != nil {
			return result, dbError("read portfolio summary")
		}
		if len(obs) >= portfolioLimit {
			return result, fmt.Errorf("portfolio exceeds %d observations; narrow project/branch/date filters (no partial totals shown)", portfolioLimit)
		}
		if err = json.Unmarshal([]byte(raw), &o.Summary); err != nil {
			return result, fmt.Errorf("invalid stored summary")
		}
		if _, err = time.Parse(stamp, o.Started); err != nil {
			return result, fmt.Errorf("invalid stored scan timestamp")
		}
		o.Complete = complete == 1
		obs = append(obs, o)
	}
	if rows.Err() != nil {
		return result, dbError("finish portfolio summary")
	}
	// SQL returns a stable order; the explicit sort also makes the in-memory
	// definition independent of a database's timestamp-string collation.
	sort.SliceStable(obs, func(i, j int) bool {
		if obs[i].Started == obs[j].Started {
			return obs[i].ID < obs[j].ID
		}
		return obs[i].Started < obs[j].Started
	})
	result.Observations = len(obs)
	if len(obs) > 0 {
		result.LatestObservedAt = obs[len(obs)-1].Started
	}
	current := map[string]observation{}
	index := 0
	for day := start; !day.After(last); day = day.AddDate(0, 0, 1) {
		boundary := day.AddDate(0, 0, 1)
		if boundary.After(now) {
			boundary = now
		}
		for index < len(obs) {
			t, _ := time.Parse(stamp, obs[index].Started)
			if t.After(boundary) || t.Equal(boundary) && boundary.Before(now) {
				break
			}
			current[obs[index].Project] = obs[index]
			index++
		}
		point := PortfolioPoint{Date: day.Format("2006-01-02"), Projects: len(current), BySeverity: map[string]int{}, ByCategory: map[string]int{}}
		for _, o := range current {
			t, _ := time.Parse(stamp, o.Started)
			if boundary.Sub(t) > 7*24*time.Hour {
				point.Stale++
			}
			if !o.Complete || o.Status == "incomplete" {
				point.Incomplete++
				continue
			}
			point.Complete++
			if o.Status == "passed" {
				point.Passed++
			} else {
				point.Failed++
			}
			point.Findings += o.Summary.Findings
			point.Failures += o.Summary.Failures
			point.Reviews += o.Summary.Reviews
			point.Components += o.Summary.Components
			for k, n := range o.Summary.BySeverity {
				point.BySeverity[k] += n
			}
			for k, n := range o.Summary.ByCategory {
				point.ByCategory[k] += n
			}
		}
		result.Points = append(result.Points, point)
		result.Current = point
	}
	return result, nil
}
