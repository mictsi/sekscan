// Package ui provides the shared, offline Sekura-derived presentation layer.
package ui

import _ "embed"

//go:embed assets/sekura.css
var CSS string

//go:embed assets/ui.js
var JS string
