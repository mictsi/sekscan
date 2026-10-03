package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"sekscan/internal/config"
	"sekscan/internal/dbstore"
	"sekscan/internal/model"
	"sekscan/internal/report"
	"sekscan/internal/store"
)

func collectArtifacts(dir string, c config.Storage) ([]dbstore.Artifact, error) {
	out := []dbstore.Artifact{}
	if !c.StoreArtifacts {
		return out, nil
	}
	for _, name := range []string{"sbom.syft.json", "sbom.cdx.json", "sbom.spdx.json"} {
		path := filepath.Join(dir, name)
		if _, e := os.Stat(path); os.IsNotExist(e) {
			continue
		}
		b, e := store.Read(path, int64(c.MaxArtifactMB)<<20)
		if e != nil {
			return nil, e
		}
		out = append(out, dbstore.Artifact{Name: name, MediaType: "application/json", Content: b})
	}
	return out, nil
}
func identifyProject(c config.Config, r *model.Report) (config.Project, error) {
	p := c.Project
	if p.Key == "" && r.ProjectKey != "" {
		p.Key = r.ProjectKey // Imported snapshots retain their explicit identity.
	}
	if err := config.RequireProject(p); err != nil {
		return p, err
	}
	if r.ProjectKey != "" && r.ProjectKey != p.Key {
		return p, fmt.Errorf("report project key differs from selected project")
	}
	if r.Namespace != "" && r.Namespace != p.Namespace {
		return p, fmt.Errorf("report namespace differs from selected namespace")
	}
	r.ProjectKey = p.Key
	r.Namespace = p.Namespace
	return p, nil
}
func openReady(ctx context.Context, c config.Config) (*dbstore.Store, error) {
	s, e := dbstore.Open(ctx, c.Storage)
	if e != nil {
		return nil, e
	}
	if c.Storage.Driver == "sqlite" && c.Storage.AutoMigrate {
		e = s.Migrate(ctx)
	} else {
		_, e = s.Status(ctx)
	}
	if e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}
func persistReport(ctx context.Context, c config.Config, r *model.Report, dir string, log *slog.Logger) {
	if !c.Storage.Enabled {
		return
	}
	p, e := identifyProject(c, r)
	if e == nil {
		var artifacts []dbstore.Artifact
		artifacts, e = collectArtifacts(dir, c.Storage)
		if e == nil {
			var db *dbstore.Store
			db, e = openReady(ctx, c)
			if e == nil {
				e = db.Save(ctx, p, r, artifacts)
				db.Close()
			}
		}
	}
	if e == nil {
		log.Info("scan persisted", "scan_id", r.ID, "driver", c.Storage.Driver)
		return
	}
	// Reports still get written locally. Required persistence failure is operational failure, not a clean gate.
	r.Warnings = append(r.Warnings, "Scan-history persistence failed: "+e.Error())
	if c.Storage.Required {
		r.Complete = false
		r.Status = "incomplete"
		r.ExitCode = 2
	}
	log.Error("scan persistence failed", "driver", c.Storage.Driver, "required", c.Storage.Required, "error", e.Error())
}
func storageCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("storage requires migrate, status, schema, import, or backup")
	}
	action := args[0]
	f := set("storage "+action, errOut)
	common := addCommon(f)
	driver := f.String("driver", "", "schema dialect: sqlite, postgres, mssql")
	dest := f.String("out", "", "schema output or SQLite backup destination")
	project := f.String("project", "", "stable project key for imported reports")
	if e := parse(f, args[1:]); e != nil {
		return e
	}
	c, e := loadCommon(ctx, common)
	if e != nil {
		return e
	}
	if *project != "" {
		c.Project.Key = *project
	}
	if action == "schema" {
		if f.NArg() != 0 {
			return fmt.Errorf("schema does not accept positional arguments")
		}
		d := *driver
		if d == "" {
			d = c.Storage.Driver
		}
		script, e := dbstore.SchemaSQL(d)
		if e != nil {
			return e
		}
		if *dest != "" {
			return store.Atomic(*dest, []byte(script), 0600)
		}
		_, e = fmt.Fprint(out, script)
		return e
	}
	if action != "migrate" && action != "status" && action != "import" && action != "backup" {
		return fmt.Errorf("unknown storage action")
	}
	if action != "import" && f.NArg() != 0 {
		return fmt.Errorf("unexpected storage arguments")
	}
	if action == "import" && f.NArg() != 1 {
		return fmt.Errorf("storage import requires a report directory or results.json")
	}
	db, e := dbstore.Open(ctx, c.Storage)
	if e != nil {
		return e
	}
	defer db.Close()
	switch action {
	case "backup":
		if *dest == "" {
			return fmt.Errorf("storage backup requires --out; existing files are never overwritten")
		}
		if e = db.BackupSQLite(ctx, *dest); e != nil {
			return e
		}
		fmt.Fprintln(out, "Consistent SQLite backup written:", *dest)
	case "migrate":
		if e = db.Migrate(ctx); e != nil {
			return e
		}
		fmt.Fprintln(out, "Database schema is current:", dbstore.SchemaVersion)
	case "status":
		v, e := db.Status(ctx)
		if e != nil {
			return e
		}
		fmt.Fprintf(out, "driver=%s schema=%d ready\n", c.Storage.Driver, v)
	case "import":
		if c.Storage.Driver == "sqlite" && c.Storage.AutoMigrate {
			e = db.Migrate(ctx)
		} else {
			_, e = db.Status(ctx)
		}
		if e != nil {
			return e
		}
		path := f.Arg(0)
		st, e := os.Stat(path)
		if e != nil {
			return e
		}
		if st.IsDir() {
			path = filepath.Join(path, "results.json")
		}
		r, e := report.Load(path)
		if e != nil {
			return e
		}
		p, e := identifyProject(c, r)
		if e != nil {
			return e
		}
		artifacts, e := collectArtifacts(filepath.Dir(path), c.Storage)
		if e != nil {
			return e
		}
		if e = db.Save(ctx, p, r, artifacts); e != nil {
			return e
		}
		fmt.Fprintln(out, "Imported", r.ID)
	}
	return nil
}
