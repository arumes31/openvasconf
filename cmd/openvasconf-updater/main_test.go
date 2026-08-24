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
