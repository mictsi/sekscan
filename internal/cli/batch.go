package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sekscan/internal/batch"
	"sekscan/internal/config"
	"sekscan/internal/model"
	"sekscan/internal/report"
	"sekscan/internal/source"
	"sekscan/internal/store"
	"sekscan/schema"
)

type scanMetadataKey struct{}
type scanMetadata struct {
	Source   *model.Source
	BatchID  string
	Complete bool
	Warnings []string
	DenyEnv  []string
}
type sourceClientKey struct{} // Test injection still observes destination allowlists.

type batchRun struct {
	Project    string     `json:"project"`
	Kind       string     `json:"kind"`
	Source     string     `json:"source"`
	Ref        string     `json:"ref,omitempty"`
	Revision   string     `json:"revision,omitempty"`
	RunID      string     `json:"run_id,omitempty"`
	Status     string     `json:"status"`
	ExitCode   int        `json:"exit_code"`
	Error      string     `json:"error,omitempty"`
	ReportDir  string     `json:"report_dir,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}
type batchResult struct {
	Version    int        `json:"version"`
	ID         string     `json:"id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Namespace  string     `json:"namespace"`
	Status     string     `json:"status"`
	ExitCode   int        `json:"exit_code"`
	Total      int        `json:"total"`
	Completed  int        `json:"completed"`
	Passed     int        `json:"passed"`
	Failed     int        `json:"failed"`
	Incomplete int        `json:"incomplete"`
	Skipped    int        `json:"skipped"`
	Items      []batchRun `json:"items"`
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func batchID() string {
	var b [8]byte
	if _, e := rand.Read(b[:]); e != nil {
		return model.Hash(time.Now().String())[:20]
	}
	return time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(b[:])
}
func fileKey(project string) string {
	var b strings.Builder
	for _, r := range project {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
		if b.Len() >= 48 {
			break
		}
	}
	return strings.Trim(b.String(), "-_") + "-" + model.Hash(project)[:10]
}
func commandSettings(f interface {
	Bool(string, bool, string) *bool
}) batch.Settings {
	return batch.Settings{Hadolint: f.Bool("hadolint", false, "override default hadolint check"), Zizmor: f.Bool("zizmor", false, "override default zizmor check"), Govulncheck: f.Bool("govulncheck", false, "override default govulncheck check"), Gosec: f.Bool("gosec", false, "override default gosec check"), Offline: f.Bool("offline", false, "use cached databases; GitHub sources require a cached exact commit"), InventoryOnly: f.Bool("inventory-only", false, "generate only inventory/SBOMs"), Gitleaks: f.Bool("gitleaks", false, "enable Gitleaks"), Actionlint: f.Bool("actionlint", false, "enable actionlint"), TrivyVuln: f.Bool("trivy-vuln", false, "enable Trivy vulnerability checks"), NoStore: f.Bool("no-store", false, "disable history persistence")}
}

// Only explicitly supplied flags override manifest defaults (including =false).
func settingsFlags(args []string, s batch.Settings) batch.Settings {
	has := func(name string) bool {
		for _, a := range args {
			if a == "--" {
				break
			}
			if a == "--"+name || strings.HasPrefix(a, "--"+name+"=") {
				return true
			}
		}
		return false
	}
	if !has("offline") {
		s.Offline = nil
	}
	if !has("inventory-only") {
		s.InventoryOnly = nil
	}
	if !has("gitleaks") {
		s.Gitleaks = nil
	}
	if !has("actionlint") {
		s.Actionlint = nil
	}
	if !has("hadolint") {
		s.Hadolint = nil
	}
	if !has("zizmor") {
		s.Zizmor = nil
	}
	if !has("govulncheck") {
		s.Govulncheck = nil
	}
	if !has("gosec") {
		s.Gosec = nil
	}
	if !has("trivy-vuln") {
		s.TrivyVuln = nil
	}
	if !has("no-store") {
		s.NoStore = nil
	}
	return s
}
func batchCommand(ctx context.Context, args []string, out, errOut io.Writer) (int, error) {
	action := "run"
	if len(args) > 0 && (args[0] == "schema" || args[0] == "validate") {
		action = args[0]
		args = args[1:]
	}
	f := set("batch "+action, errOut)
	common := addCommon(f)
	file := f.String("file", "", "batch manifest (or supply one positional path)")
	dest := f.String("out", "batch-reports", "root for a new batch output directory")
	dry := f.Bool("dry-run", false, "validate and print the plan without downloads or scans")
	asJSON := f.Bool("json", false, "write the plan or final batch summary as JSON")
	failFast := f.Bool("fail-fast", false, "stop after the first nonzero scan result")
	tokenEnv := f.String("token-env", "GITHUB_TOKEN", "environment variable containing a GitHub token")
	flags := commandSettings(f)
	if e := parse(f, args); e != nil {
		return 0, e
	}
	if action == "schema" {
		if f.NArg() != 0 || *file != "" {
			return 0, fmt.Errorf("batch schema takes no manifest")
		}
		_, e := out.Write(schema.Batch)
		return 0, e
	}
	if f.NArg() > 1 || f.NArg() == 1 && *file != "" {
		return 0, fmt.Errorf("batch requires exactly one manifest path")
	}
	if f.NArg() == 1 {
		*file = f.Arg(0)
	}
	if *file == "" {
		return 0, fmt.Errorf("batch requires FILE.json or --file FILE.json")
	}
	m, jobs, e := batch.Load(*file)
	if e != nil {
		return 0, e
	}
	override := settingsFlags(args, flags)
	for i := range jobs {
		jobs[i].Settings = batch.Merge(jobs[i].Settings, override)
	}
	if !envName.MatchString(*tokenEnv) {
		return 0, fmt.Errorf("invalid token environment-variable name")
	}
	if *dry || action == "validate" {
		if *asJSON || *dry {
			return 0, json.NewEncoder(out).Encode(map[string]any{"valid": true, "projects": jobs})
		}
		fmt.Fprintf(out, "Batch is valid: %d projects. No downloads or scans performed.\n", len(jobs))
		return 0, nil
	}
	c, e := loadCommon(ctx, common)
	if e != nil {
		return 0, e
	}
	keepGoing := m.ContinueOnError == nil || *m.ContinueOnError
	if *failFast {
		keepGoing = false
	}
	return executeBatch(ctx, c, common, jobs, *dest, *tokenEnv, keepGoing, *asJSON, out, errOut)
}
func githubCommand(ctx context.Context, args []string, out, errOut io.Writer) (int, error) {
	f := set("github", errOut)
	common := addCommon(f)
	project := f.String("project", "", "project key (defaults to lowercase owner/repository)")
	ref := f.String("ref", "", "branch, tag, or full commit; defaults to the repository's default branch")
	subdir := f.String("subdir", "", "relative repository subdirectory")
	dest := f.String("out", "github-reports", "root for this run's report directory")
	token := f.String("token-env", "GITHUB_TOKEN", "environment variable containing a GitHub token")
	dry := f.Bool("dry-run", false, "print the plan without downloading or scanning")
	asJSON := f.Bool("json", false, "write the plan or result as JSON")
	flags := commandSettings(f)
	if e := parse(f, args); e != nil {
		return 0, e
	}
	if f.NArg() != 1 {
		return 0, fmt.Errorf("github requires one repository URL or owner/repo")
	}
	m := batch.Manifest{Version: 1, Projects: []batch.Entry{{Project: *project, RepoURL: f.Arg(0), Ref: *ref, Subdir: *subdir, Settings: settingsFlags(args, flags)}}}
	jobs, e := m.Plan("")
	if e != nil {
		return 0, e
	}
	if !envName.MatchString(*token) {
		return 0, fmt.Errorf("invalid token environment-variable name")
	}
	if *dry {
		return 0, json.NewEncoder(out).Encode(map[string]any{"valid": true, "projects": jobs})
	}
	c, e := loadCommon(ctx, common)
	if e != nil {
		return 0, e
	}
	return executeBatch(ctx, c, common, jobs, *dest, *token, true, *asJSON, out, errOut)
}
func configureJob(c config.Config, j batch.Job) config.Config {
	c.Project.Key = j.Project
	c.Project.Name = j.Project
	c.Project.Repository = j.RepoURL
	s := j.Settings
	if s.Gitleaks != nil {
		c.Checks.Gitleaks = *s.Gitleaks
	}
	if s.Actionlint != nil {
		c.Checks.Actionlint = *s.Actionlint
	}
	if s.Hadolint != nil {
		c.Checks.Hadolint = *s.Hadolint
	}
	if s.Zizmor != nil {
		c.Checks.Zizmor = *s.Zizmor
	}
	if s.Govulncheck != nil {
		c.Checks.Govulncheck = *s.Govulncheck
	}
	if s.Gosec != nil {
		c.Checks.Gosec = *s.Gosec
	}
	if s.TrivyVuln != nil {
		c.Checks.TrivyVulnerabilities = *s.TrivyVuln
	}
	if s.NoStore != nil {
		c.Storage.Enabled = !*s.NoStore
	}
	// A copy of this slice avoids cross-job exclusions leaking through shared capacity.
	c.Exclude = append([]string{}, c.Exclude...)
	return c
}
func executeBatch(ctx context.Context, c config.Config, common *common, jobs []batch.Job, dest, tokenEnv string, keepGoing, asJSON bool, out, errOut io.Writer) (int, error) {
	id := batchID()
	root, e := filepath.Abs(filepath.Join(dest, id))
	if e != nil {
		return 0, e
	}
	for _, j := range jobs {
		if j.Kind == "directory" && filepath.Clean(j.Path) == filepath.Dir(root) {
			return 2, fmt.Errorf("batch output root cannot equal a source directory; select a dedicated report subdirectory")
		}
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return 0, e
	}
	result := batchResult{Version: 1, ID: id, Namespace: c.Project.Namespace, StartedAt: time.Now().UTC(), Status: "running", Total: len(jobs), Items: make([]batchRun, len(jobs))}
	for i, j := range jobs {
		input := j.Path
		if j.Kind == "github" {
			input = j.RepoURL
		}
		result.Items[i] = batchRun{Project: j.Project, Kind: j.Kind, Source: input, Ref: j.Ref, Status: "queued", ExitCode: 2}
	}
	summaryFile := filepath.Join(root, "batch-results.json")
	write := func() error { return store.JSON(summaryFile, result) }
	if e = write(); e != nil {
		return 0, e
	}
	progress := out
	if asJSON {
		progress = errOut
	}
	log := logger(common, errOut)
	stopped := false
	for i, j := range jobs {
		item := &result.Items[i]
		if stopped || ctx.Err() != nil {
			item.Status = "skipped"
			item.Error = "Not attempted because the batch stopped or was cancelled"
			result.Skipped++
			result.ExitCode = 2
			continue
		}
		now := time.Now().UTC()
		item.StartedAt = &now
		item.Status = "running"
		if e = write(); e != nil {
			return 2, e
		}
		jc := configureJob(c, j)
		// Do not accidentally include previous jobs' report trees in a later source scan.
		if j.Kind == "directory" {
			if rel, err := filepath.Rel(j.Path, filepath.Dir(root)); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				jc.Exclude = append(jc.Exclude, filepath.ToSlash(rel))
			}
		}
		output := filepath.Join(root, fmt.Sprintf("%04d-%s", i+1, fileKey(j.Project)))
		item.ReportDir = filepath.Base(output)
		log.Info("batch project started", "batch_id", id, "project", j.Project, "position", i+1, "total", len(jobs), "kind", j.Kind)
		runID, revision, code, err := runJob(ctx, jc, common, j, id, output, tokenEnv, progress, errOut)
		item.RunID, item.Revision, item.ExitCode = runID, revision, code
		item.Status = "passed"
		if code == 1 {
			item.Status = "failed"
		}
		if code >= 2 {
			item.Status = "incomplete"
		}
		if err != nil {
			item.Error = err.Error()
			item.Status = "incomplete"
			item.ExitCode = 2
		}
		end := time.Now().UTC()
		item.FinishedAt = &end
		result.Completed++
		switch item.Status {
		case "passed":
			result.Passed++
		case "failed":
			result.Failed++
		default:
			result.Incomplete++
		}
		result.ExitCode = max(result.ExitCode, item.ExitCode)
		log.Info("batch project finished", "batch_id", id, "project", j.Project, "status", item.Status, "exit_code", item.ExitCode)
		if !keepGoing && item.ExitCode != 0 {
			stopped = true
		}
		if e = write(); e != nil {
			return 2, e
		}
	}
	finish := time.Now().UTC()
	result.FinishedAt = &finish
	result.Status = "passed"
	if result.ExitCode == 1 {
		result.Status = "failed"
	}
	if result.ExitCode >= 2 {
		result.Status = "incomplete"
	}
	if e = write(); e != nil {
		return 2, e
	}
	if asJSON {
		e = json.NewEncoder(out).Encode(result)
	} else {
		fmt.Fprintf(out, "Batch %s: %d passed, %d failed policy, %d incomplete, %d skipped\nSummary: %s\n", result.ID, result.Passed, result.Failed, result.Incomplete, result.Skipped, summaryFile)
	}
	return result.ExitCode, e
}
func runJob(ctx context.Context, c config.Config, common *common, j batch.Job, id, output, tokenEnv string, out, errOut io.Writer) (runID, revision string, code int, err error) {
	meta := scanMetadata{BatchID: id, Complete: true, DenyEnv: []string{tokenEnv}}
	target := "dir:" + j.Path
	branch := ""
	if j.Kind == "github" {
		repo, _ := source.ParseRepository(j.RepoURL)
		client := &source.Client{Cache: c.Paths.Cache, Token: os.Getenv(tokenEnv)}
		if injected, ok := ctx.Value(sourceClientKey{}).(*source.Client); ok {
			copy := *injected
			copy.Cache = c.Paths.Cache
			copy.Token = os.Getenv(tokenEnv)
			client = &copy
		}
		snapshot, e := client.Acquire(ctx, repo, j.Ref, j.Subdir, batch.Enabled(j.Settings.Offline))
		if e != nil {
			meta.Source = &model.Source{Provider: "github", Repository: j.RepoURL, RequestedRef: j.Ref, Subdir: j.Subdir}
			runID = failureReport(ctx, c, meta, j, output, e, common, errOut)
			return runID, "", 2, e
		}
		defer snapshot.Close()
		revision = snapshot.Revision
		branch = snapshot.ResolvedRef
		if branch == revision {
			branch = ""
		} // A detached commit is not a branch.
		meta.Source = &model.Source{Provider: "github", Repository: snapshot.Repository, RequestedRef: snapshot.RequestedRef, ResolvedRef: snapshot.ResolvedRef, Revision: revision, Subdir: j.Subdir, ArchiveSHA256: snapshot.ArchiveSHA256}
		meta.Warnings, meta.Complete = snapshot.Warnings, snapshot.Complete
		target = "dir:" + snapshot.Path
	}
	rt := &appRuntime{Config: c}
	if old, ok := ctx.Value(runtimeKey{}).(*appRuntime); ok {
		rt.Selection = old.Selection
	}
	jobCtx := context.WithValue(context.WithValue(ctx, runtimeKey{}, rt), scanMetadataKey{}, meta)
	args := []string{target, "--project", j.Project, "--out", output}
	if revision != "" {
		args = append(args, "--revision", revision, "--branch", branch)
	}
	if batch.Enabled(j.Settings.Offline) {
		args = append(args, "--offline")
	}
	if batch.Enabled(j.Settings.InventoryOnly) {
		args = append(args, "--inventory-only")
	}
	if common.logJSON {
		args = append(args, "--log-json")
	}
	code, err = scanCommand(jobCtx, args, out, errOut)
	if err != nil {
		return failureReport(ctx, c, meta, j, output, err, common, errOut), revision, 2, err
	}
	r, e := report.Load(filepath.Join(output, "results.json"))
	if e != nil {
		return "", revision, 2, fmt.Errorf("scan result could not be read")
	}
	return r.ID, revision, code, nil
}
func failureReport(ctx context.Context, c config.Config, meta scanMetadata, j batch.Job, output string, cause error, common *common, errOut io.Writer) string {
	now := time.Now().UTC()
	input := j.Path
	if j.Kind == "github" {
		input = j.RepoURL
	}
	r := &model.Report{SchemaVersion: model.SchemaVersion, AppVersion: Version, ID: model.Hash(meta.BatchID, j.Project, now.String())[:24], ProjectKey: j.Project, Namespace: c.Project.Namespace, StartedAt: now, FinishedAt: now, Target: model.Target{Kind: "dir", Value: input, Identity: input}, ConfigHash: c.Hash(), Source: meta.Source, BatchID: meta.BatchID, Components: []model.Component{}, Findings: []model.Finding{}, Resolved: []model.Finding{}, Warnings: []string{"No successful assessment was completed for this entry."}, Engines: []model.EngineRun{{Name: "source", Status: "failed", Required: true, Checks: []string{"source"}, Error: cause.Error()}}}
	r.Summarize(c.Policy.FailOnReview)
	cleanup, e := prepareOutput(output)
	if e != nil {
		fmt.Fprintln(errOut, "Could not write failed-entry report:", e)
		return ""
	}
	defer cleanup()
	// A cancelled context must not fabricate successful persistence.
	persistReport(ctx, c, r, output, logger(common, errOut))
	if e = report.Write(output, r); e != nil {
		fmt.Fprintln(errOut, "Could not write failed-entry report:", e)
		return ""
	}
	return r.ID
}
