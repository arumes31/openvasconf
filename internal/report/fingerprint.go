// Package report implements the report snapshot domain: stable finding
// fingerprints, normalization of Greenbone reports into snapshots, and the
// bounded report synchronization service.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// FingerprintVersion identifies the fingerprint encoding. Bumping the version
// changes every fingerprint deliberately so future identity changes never
// silently rewrite finding identity.
const FingerprintVersion = "v1"

// Fingerprint derives the stable identity of a finding from the customer, the
// NVT OID, and the affected host, port, and location. Fields are separated
// with NUL bytes so concatenation ambiguities are impossible. The result is
// prefixed with the fingerprint version.
func Fingerprint(customerID, nvtOID, host, port, location string) string {
	digest := sha256.Sum256([]byte(strings.Join(
		[]string{customerID, nvtOID, host, port, location},
		"\x00",
	)))
	return FingerprintVersion + ":" + hex.EncodeToString(digest[:])
}
