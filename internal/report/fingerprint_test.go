package report

import (
	"strings"
	"testing"
)

func TestFingerprintStableAndVersioned(t *testing.T) {
	t.Parallel()

	first := Fingerprint("customer-1", "1.3.6.1.4.1.25623.1.0.1", "10.0.0.1", "22/tcp", "")
	second := Fingerprint("customer-1", "1.3.6.1.4.1.25623.1.0.1", "10.0.0.1", "22/tcp", "")
	if first != second {
		t.Fatalf("fingerprint not stable: %q vs %q", first, second)
	}
	if !strings.HasPrefix(first, FingerprintVersion+":") {
		t.Errorf("fingerprint %q misses version prefix", first)
	}
	if len(first) != len(FingerprintVersion)+1+64 {
		t.Errorf("fingerprint %q has unexpected length", first)
	}
}

func TestFingerprintChangesPerField(t *testing.T) {
	t.Parallel()

	base := Fingerprint("customer-1", "oid", "10.0.0.1", "22/tcp", "")
	variants := []string{
		Fingerprint("customer-2", "oid", "10.0.0.1", "22/tcp", ""),
		Fingerprint("customer-1", "other-oid", "10.0.0.1", "22/tcp", ""),
		Fingerprint("customer-1", "oid", "10.0.0.2", "22/tcp", ""),
		Fingerprint("customer-1", "oid", "10.0.0.1", "80/tcp", ""),
		Fingerprint("customer-1", "oid", "10.0.0.1", "22/tcp", "/some/path"),
	}
	for index, variant := range variants {
		if variant == base {
			t.Errorf("variant %d collides with base fingerprint", index)
		}
	}
}

func TestFingerprintAmbiguityFree(t *testing.T) {
	t.Parallel()

	// Field boundaries must not be forgeable by shifting content between
	// adjacent fields.
	left := Fingerprint("ab", "c", "host", "port", "")
	right := Fingerprint("a", "bc", "host", "port", "")
	if left == right {
		t.Fatal("fingerprint is ambiguous across field boundaries")
	}
}
