package auth

import (
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   map[string]string
		expectKey string
		expectErr bool
	}{
		{
			name:      "No Authorization header",
			headers:   map[string]string{},
			expectKey: "",
			expectErr: true,
		},
		{
			name:      "Malformed Authorization header (missing ApiKey)",
			headers:   map[string]string{"Authorization": "Bearer sometoken"},
			expectKey: "",
			expectErr: true,
		},
		{
			name:      "Malformed Authorization header (no value)",
			headers:   map[string]string{"Authorization": "ApiKey"},
			expectKey: "",
			expectErr: true,
		},
		{
			name:      "Valid ApiKey header",
			headers:   map[string]string{"Authorization": "ApiKey my-secret-key"},
			expectKey: "my-secret-key",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := make(map[string][]string)
			for k, v := range tt.headers {
				hdr[k] = []string{v}
			}
			key, err := GetAPIKey(hdr)
			if tt.expectErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("did not expect error, got %v", err)
			}
			if key != tt.expectKey {
				t.Errorf("expected key %q, got %q", tt.expectKey, key)
			}
		})
	}
}
