// Package webui exposes the compiled React UI as an embedded filesystem.
package webui

import "embed"

//go:embed all:dist
var FS embed.FS
