package store

import (
	"context"
	"path/filepath"
	"testing"

	"openvasconf/internal/updater"
)

func TestUpdatePolicyRoundTrip(t *testing.T) {
	repository, err := Open(
		context.Background(),
		filepath.Join(t.TempDir(), "openvasconf.db"),
		"Europe/Vienna",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })

	policy, err := repository.UpdatePolicy(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !policy.FeedEnabled || policy.StackEnabled || policy.Timezone != "Europe/Vienna" {
		t.Fatalf("default policy = %#v", policy)
	}

	policy.StackEnabled = true
	policy.StackWeekday = 6
	policy.StackStartMinute = 4 * 60
	policy.StackWindowMinutes = 90
	policy.BackupRetention = 5
	if err := repository.SaveUpdatePolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.UpdatePolicy(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if stored != policy {
		t.Fatalf("stored policy = %#v, want %#v", stored, policy)
	}

	invalid := updater.DefaultPolicy("UTC")
	invalid.BackupRetention = 0
	if err := repository.SaveUpdatePolicy(t.Context(), invalid); err == nil {
		t.Fatal("SaveUpdatePolicy(invalid) error = nil")
	}
}
