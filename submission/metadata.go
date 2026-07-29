package submission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Metadata mirrors the schema in prd.md ("Metadata" / "Metadata
// Schema").
type Metadata struct {
	ValidatorAddress string `json:"validator_address"`
	Moniker          string `json:"moniker"`

	ChainID        string `json:"chain_id"`
	GnolandVersion string `json:"gnoland_version"`
	GenesisSHA256  string `json:"genesis_sha256"`

	OperatingSystem string `json:"operating_system"`
	Architecture    string `json:"architecture"`

	SentryEnabled bool `json:"sentry_enabled"`
	BackupNode    bool `json:"backup_node"`

	HostingProvider  string `json:"hosting_provider"`
	DeploymentMethod string `json:"deployment_method"`

	RecentOperations string `json:"recent_operations"`
}

var (
	allowedArchitectures = map[string]bool{
		"amd64": true,
		"arm64": true,
		"x86":   true,
	}

	allowedDeploymentMethods = map[string]bool{
		"docker":     true,
		"systemd":    true,
		"binary":     true,
		"kubernetes": true,
	}

	// requiredFields lists every field validated for presence below,
	// used only to build a readable error message. It intentionally
	// mirrors prd.md's example metadata.json minus "recent_operations"
	// (explicitly optional/conditional — "any recent operations that
	// may be relevant") and the two booleans (a missing bool is
	// indistinguishable from an explicit `false` in Go's zero value, so
	// presence can't be meaningfully enforced without switching to
	// pointer fields — not worth the complexity here). This is an
	// interpretation of the PRD, not something it states explicitly;
	// easy to tighten or loosen field-by-field if that turns out wrong.
	requiredFields = []struct {
		name  string
		value func(Metadata) string
	}{
		{"validator_address", func(m Metadata) string { return m.ValidatorAddress }},
		{"moniker", func(m Metadata) string { return m.Moniker }},
		{"chain_id", func(m Metadata) string { return m.ChainID }},
		{"gnoland_version", func(m Metadata) string { return m.GnolandVersion }},
		{"genesis_sha256", func(m Metadata) string { return m.GenesisSHA256 }},
		{"operating_system", func(m Metadata) string { return m.OperatingSystem }},
		{"architecture", func(m Metadata) string { return m.Architecture }},
		{"hosting_provider", func(m Metadata) string { return m.HostingProvider }},
		{"deployment_method", func(m Metadata) string { return m.DeploymentMethod }},
	}
)

// ValidateMetadata parses data against the Metadata schema and enforces
// the enum constraints from prd.md's "Metadata Schema" table.
// DisallowUnknownFields is deliberate: the PRD states additional enum
// *values* may be added later, not additional unknown *fields* — an
// unrecognized field is more likely a typo or a schema-version mismatch
// than something to silently ignore.
func ValidateMetadata(data []byte) (Metadata, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var m Metadata
	if err := dec.Decode(&m); err != nil {
		return Metadata{}, fmt.Errorf("metadata.json does not match the expected schema: %w", err)
	}

	var missing []string
	for _, f := range requiredFields {
		if f.value(m) == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return Metadata{}, fmt.Errorf("metadata.json is missing required field(s): %s", strings.Join(missing, ", "))
	}

	if !allowedArchitectures[m.Architecture] {
		return Metadata{}, fmt.Errorf("metadata.json: architecture %q is not one of the allowed values", m.Architecture)
	}
	if !allowedDeploymentMethods[m.DeploymentMethod] {
		return Metadata{}, fmt.Errorf("metadata.json: deployment_method %q is not one of the allowed values", m.DeploymentMethod)
	}

	return m, nil
}
