package submission

import "testing"

func TestValidateFilename(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		wantMoniker string
		wantErr     bool
	}{
		{
			name:        "example from prd.md",
			filename:    "samourai-20260709-1830UTC.tar.gz",
			wantMoniker: "samourai",
		},
		{
			name:        "moniker containing hyphens",
			filename:    "samourai-eu-1-20260709-1830UTC.tar.gz",
			wantMoniker: "samourai-eu-1",
		},
		{
			name:     "missing .tar.gz",
			filename: "samourai-20260709-1830UTC.zip",
			wantErr:  true,
		},
		{
			name:     "missing timestamp",
			filename: "samourai.tar.gz",
			wantErr:  true,
		},
		{
			name:     "invalid date",
			filename: "samourai-20261399-1830UTC.tar.gz",
			wantErr:  true,
		},
		{
			name:     "path traversal via moniker",
			filename: "../../etc-20260709-1830UTC.tar.gz",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			moniker, _, err := ValidateFilename(tt.filename)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ValidateFilename(%q) = nil error, want error", tt.filename)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateFilename(%q) unexpected error: %v", tt.filename, err)
			}
			if moniker != tt.wantMoniker {
				t.Errorf("moniker = %q, want %q", moniker, tt.wantMoniker)
			}
		})
	}
}
