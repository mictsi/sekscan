package cli

import (
	"context"
	"fmt"
	"io"
	"sekscan/internal/deps"
	"sekscan/internal/workspace"
	"strings"
)

func initCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	f := set("init", errOut)
	_ = addCommon(f)
	if e := parse(f, args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("init accepts no positional arguments")
	}
	rt, ok := ctx.Value(runtimeKey{}).(*appRuntime)
	if !ok {
		return fmt.Errorf("workspace is not initialized")
	}
	names, e := workspace.Initialize(rt.Selection.Root, rt.Selection.File == "")
	if e != nil {
		return e
	}
	fmt.Fprintln(out, "Workspace ready:", rt.Selection.Root, "(existing files preserved)")
	for _, n := range names {
		fmt.Fprintln(out, " ", n)
	}
	return nil
}
func prepareCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	f := set("prepare", errOut)
	common := addCommon(f)
	yes := f.Bool("yes", false, "approve executable and vulnerability database downloads")
	all := f.Bool("all", false, "prepare all configured tools")
	update := f.Bool("update-tools", false, "upgrade unpinned managed tools after checking releases")
	skipDB := f.Bool("skip-db", false, "skip vulnerability database downloads")
	goModule := f.String("go-module", "", "explicitly download dependencies for one Go module into the workspace cache (may update go.sum)")
	java := f.Bool("with-java", false, "also download the Trivy Java database")
	if e := parse(f, args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("prepare accepts no positional arguments")
	}
	if !*yes {
		return fmt.Errorf("prepare downloads executable software and requires --yes")
	}
	c, e := loadCommon(ctx, common)
	if e != nil {
		return e
	}
	rt, _ := ctx.Value(runtimeKey{}).(*appRuntime)
	if rt != nil {
		if _, e = workspace.Initialize(rt.Selection.Root, rt.Selection.File == ""); e != nil {
			return e
		}
	}
	manager := deps.NewConfigured(common.tools, c)
	log := logger(common, errOut)
	log.Info("preparation workspace", "bin", manager.Dir, "cache", c.Paths.Cache, "portable", c.Portable)
	failures := []string{}
	names := deps.ToolNames(c, *all)
	if *java {
		has := false
		for _, name := range names {
			if name == "trivy" {
				has = true
			}
		}
		if !has {
			names = append(names, "trivy")
		}
	}
	for _, name := range names {
		t := c.Tools[name]
		status := manager.Inspect(ctx, name, t)
		u := manager.CheckUpdate(ctx, name, t)
		fmt.Fprintf(out, "%-14s installed=%-12s latest=%-12s %s\n", name, u.Installed, u.Latest, u.State)
		if u.State == "unknown" && u.Error != "" {
			failures = append(failures, name+": update check failed")
		}
		install := status.Error != ""
		upgrade := *update && u.UpdateAvailable && t.Version == "latest" && (c.Portable || t.Path == "") && t.SHA256 == ""
		if install || upgrade {
			log.Info("preparing prerequisite", "tool", name)
			entry, e := manager.Install(ctx, name, t)
			if e != nil {
				log.Error("prerequisite preparation failed", "tool", name, "error", e.Error())
				failures = append(failures, name+": "+e.Error())
				continue
			}
			probe := t
			probe.Version = entry.Version
			if verified := manager.Inspect(ctx, name, probe); verified.Error != "" {
				log.Error("prerequisite verification failed", "tool", name, "error", verified.Error)
				failures = append(failures, name+": installed executable failed version verification: "+verified.Error)
				continue
			}
			fmt.Fprintf(out, "Prepared %s %s\n", name, entry.Version)
		}
	}
	if *goModule != "" {
		if e = manager.WarmGoModule(ctx, *goModule); e != nil {
			failures = append(failures, "Go module cache: "+e.Error())
		}
	}
	if !*skipDB {
		dbArgs := append([]string{"update"}, runtimeOptions(ctx)...)
		if *all {
			dbArgs = append(dbArgs, "--all")
		}
		if *java {
			dbArgs = append(dbArgs, "--with-java")
		}
		if e = dbCommand(ctx, dbArgs, out, errOut); e != nil {
			failures = append(failures, "database update: "+e.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("prepare did not complete: %s", strings.Join(failures, "; "))
	}
	fmt.Fprintln(out, "Tools and selected scanner data are prepared; no scan was run.")
	return nil
}
