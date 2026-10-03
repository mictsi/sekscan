// Package schema exposes the canonical batch manifest schema for the CLI.
package schema

import _ "embed"

//go:embed batch.schema.json
var Batch []byte
