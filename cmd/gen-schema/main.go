// Command gen-schema generates config.schema.json from the Go config types and
// the permission catalog. Run via: go generate ./internal/perm
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/invopop/jsonschema"
	orderedmap "github.com/pb33f/ordered-map/v2"

	"github.com/abinnovision/gh-token-broker/internal/config"
	"github.com/abinnovision/gh-token-broker/internal/perm"
)

func main() {
	r := &jsonschema.Reflector{
		Anonymous:                  true,
		DoNotReference:             true,
		FieldNameTag:               "yaml",
		RequiredFromJSONSchemaTags: true,
		Mapper:                     mapper,
	}

	schema := r.Reflect(&config.Config{})

	schema.Version = "https://json-schema.org/draft/2020-12/schema"
	schema.ID = "https://github.com/abinnovision/gh-token-broker/config.schema.json"
	schema.Title = "gh-token-broker configuration"
	schema.Definitions = nil

	setAdditionalPropertiesFalse(schema)
	extractDefs(schema)

	out, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal schema: %v\n", err)
		os.Exit(1)
	}

	outPath := filepath.Join(moduleRoot(), "config.schema.json")
	if err := os.WriteFile(outPath, append(out, '\n'), 0o600); err != nil { //nolint:gosec // G306: generated schema is not sensitive
		fmt.Fprintf(os.Stderr, "write schema: %v\n", err)
		os.Exit(1)
	}
}

func mapper(t reflect.Type) *jsonschema.Schema {
	if t == reflect.TypeOf(config.Permissions{}) {
		return permissionsSchema()
	}
	return nil
}

func permissionsSchema() *jsonschema.Schema {
	props := orderedmap.New[string, *jsonschema.Schema]()

	keys := make([]string, 0, len(perm.Catalog))
	for k := range perm.Catalog {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		levels := perm.Catalog[key]
		enum := make([]any, len(levels))
		for i, l := range levels {
			enum[i] = l
		}
		props.Set(key, &jsonschema.Schema{Enum: enum})
	}

	minProps := uint64(1)
	return &jsonschema.Schema{
		Type:                 "object",
		Properties:           props,
		MinProperties:        &minProps,
		AdditionalProperties: jsonschema.FalseSchema,
	}
}

func setAdditionalPropertiesFalse(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	if s.Type == "object" && s.Properties != nil && s.AdditionalProperties == nil {
		s.AdditionalProperties = jsonschema.FalseSchema
	}
	if s.Properties != nil {
		for pair := s.Properties.Oldest(); pair != nil; pair = pair.Next() {
			setAdditionalPropertiesFalse(pair.Value)
		}
	}
	if s.Items != nil {
		setAdditionalPropertiesFalse(s.Items)
	}
}

func moduleRoot() string {
	out, err := exec.CommandContext(context.Background(), "go", "env", "GOMOD").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "find module root: %v\n", err)
		os.Exit(1)
	}
	return filepath.Dir(strings.TrimSpace(string(out)))
}

// extractDefs moves the policies item schema into $defs with $ref pointers,
// matching the canonical schema layout.
func extractDefs(s *jsonschema.Schema) {
	policies, ok := s.Properties.Get("policies")
	if !ok || policies.Items == nil {
		return
	}

	policySchema := policies.Items
	var grantSchema *jsonschema.Schema
	var permSchema *jsonschema.Schema

	if g, ok := policySchema.Properties.Get("grant"); ok {
		grantSchema = g
		if p, ok := g.Properties.Get("permissions"); ok {
			permSchema = p
			g.Properties.Set("permissions", &jsonschema.Schema{Ref: "#/$defs/permissions"})
		}
	}
	if grantSchema != nil {
		policySchema.Properties.Set("grant", &jsonschema.Schema{Ref: "#/$defs/grant"})
	}
	policies.Items = &jsonschema.Schema{Ref: "#/$defs/policy"}

	s.Definitions = jsonschema.Definitions{
		"permissions": permSchema,
		"grant":       grantSchema,
		"policy":      policySchema,
	}
}
