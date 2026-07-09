// Package githubappproxy holds root-level embedded assets, mirroring the
// reference repo's root-package pattern.
package githubappproxy

import _ "embed"

// ConfigSchema is the JSON Schema (draft 2020-12) for the YAML config file.
//
//go:embed config.schema.json
var ConfigSchema []byte
