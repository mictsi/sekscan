package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sekscan/internal/deps"
)

func importToolCommand(ctx context.Context, args []string, out, errOut io.Writer) error {
	f := set("deps import", errOut)
	common := addCommon(f)
	from := f.String("from", "", "directory containing the complete reviewed portable bundle")
	version := f.String("version", "", "exact semantic version")
	entry := f.String("executable", "", "relative executable path within bundle")
	prefix := f.String("command-args", "[]", "JSON argument prefix; {tool_dir} resolves after relocation")
	yes := f.Bool("yes", false, "approve execution of imported software")
	if err := parse(f, args); err != nil {
		return err
	}
	if f.NArg() != 1 || *from == "" || *entry == "" || *version == "" || !*yes {
		return fmt.Errorf("deps import NAME requires --from --executable --version and --yes")
	}
	var argv []string
	if err := json.Unmarshal([]byte(*prefix), &argv); err != nil {
		return fmt.Errorf("command-args must be a JSON string array")
	}
	c, err := loadCommon(ctx, common)
	if err != nil {
		return err
	}
	m := deps.NewConfigured(common.tools, c)
	installed, err := m.ImportBundle(ctx, f.Arg(0), *version, *from, *entry, argv)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(installed)
}
