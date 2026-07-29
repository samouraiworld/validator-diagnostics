package submission

import "testing"

func TestValidateMetadata_Valid(t *testing.T) {
	m, err := ValidateMetadata(validMetadataContent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Moniker != "samourai" {
		t.Errorf("Moniker = %q, want %q", m.Moniker, "samourai")
	}
	if m.Architecture != "amd64" {
		t.Errorf("Architecture = %q, want %q", m.Architecture, "amd64")
	}
}

func TestValidateMetadata_RejectsInvalidJSON(t *testing.T) {
	_, err := ValidateMetadata([]byte(`{not json`))
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}

func TestValidateMetadata_RejectsUnknownField(t *testing.T) {
	data := []byte(`{
		"validator_address": "g1abc",
		"moniker": "samourai",
		"chain_id": "topaz-1",
		"gnoland_version": "v1.0.0",
		"genesis_sha256": "deadbeef",
		"operating_system": "Debian 12",
		"architecture": "amd64",
		"hosting_provider": "Scaleway",
		"deployment_method": "docker",
		"totally_unexpected_field": true
	}`)

	if _, err := ValidateMetadata(data); err == nil {
		t.Fatal("expected an error for an unknown field, got nil")
	}
}

func TestValidateMetadata_RejectsMissingRequiredField(t *testing.T) {
	data := []byte(`{
		"moniker": "samourai",
		"chain_id": "topaz-1",
		"gnoland_version": "v1.0.0",
		"genesis_sha256": "deadbeef",
		"operating_system": "Debian 12",
		"architecture": "amd64",
		"hosting_provider": "Scaleway",
		"deployment_method": "docker"
	}`)

	if _, err := ValidateMetadata(data); err == nil {
		t.Fatal("expected an error for a missing validator_address, got nil")
	}
}

func TestValidateMetadata_RejectsInvalidArchitecture(t *testing.T) {
	data := []byte(`{
		"validator_address": "g1abc",
		"moniker": "samourai",
		"chain_id": "topaz-1",
		"gnoland_version": "v1.0.0",
		"genesis_sha256": "deadbeef",
		"operating_system": "Debian 12",
		"architecture": "sparc64",
		"hosting_provider": "Scaleway",
		"deployment_method": "docker"
	}`)

	if _, err := ValidateMetadata(data); err == nil {
		t.Fatal("expected an error for an unsupported architecture, got nil")
	}
}

func TestValidateMetadata_RejectsInvalidDeploymentMethod(t *testing.T) {
	data := []byte(`{
		"validator_address": "g1abc",
		"moniker": "samourai",
		"chain_id": "topaz-1",
		"gnoland_version": "v1.0.0",
		"genesis_sha256": "deadbeef",
		"operating_system": "Debian 12",
		"architecture": "amd64",
		"hosting_provider": "Scaleway",
		"deployment_method": "bare-metal-ssh"
	}`)

	if _, err := ValidateMetadata(data); err == nil {
		t.Fatal("expected an error for an unsupported deployment_method, got nil")
	}
}

func TestValidateMetadata_RejectsNonBooleanFlag(t *testing.T) {
	data := []byte(`{
		"validator_address": "g1abc",
		"moniker": "samourai",
		"chain_id": "topaz-1",
		"gnoland_version": "v1.0.0",
		"genesis_sha256": "deadbeef",
		"operating_system": "Debian 12",
		"architecture": "amd64",
		"hosting_provider": "Scaleway",
		"deployment_method": "docker",
		"sentry_enabled": "yes"
	}`)

	if _, err := ValidateMetadata(data); err == nil {
		t.Fatal("expected an error for a non-boolean sentry_enabled, got nil")
	}
}
