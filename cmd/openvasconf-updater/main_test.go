package main

import "testing"

func TestScanIsActive(t *testing.T) {
	t.Parallel()
	for _, status := range []string{
		"Running", "Requested", "Queued", "Processing", "Stop Requested", "Resume Requested",
	} {
		if !scanIsActive(status) {
			t.Errorf("scanIsActive(%q) = false, want true", status)
		}
	}
	for _, status := range []string{"Done", "Stopped", "Interrupted", "Internal Error", "New"} {
		if scanIsActive(status) {
			t.Errorf("scanIsActive(%q) = true, want false", status)
		}
	}
}

func TestValidateImmutableImage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:  "digest",
			value: "ghcr.io/arumes31/openvasconf-updater@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name:  "tag plus digest",
			value: "ghcr.io/arumes31/openvasconf-updater:v1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{name: "empty", wantErr: true},
		{name: "mutable tag", value: "ghcr.io/arumes31/openvasconf-updater:edge", wantErr: true},
		{name: "short digest", value: "image@sha256:abcd", wantErr: true},
		{
			name:    "non hexadecimal digest",
			value:   "image@sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateImmutableImage(test.value)
			if (err != nil) != test.wantErr {
				t.Errorf("validateImmutableImage(%q) error = %v, wantErr %t", test.value, err, test.wantErr)
			}
		})
	}
}
