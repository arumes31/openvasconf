package report

import (
	"openvasconf/internal/store"
)

// Lifecycle states of a finding relative to the preceding snapshot.
const (
	// LifecycleNew marks fingerprints present only in the newer snapshot.
	LifecycleNew = "new"
	// LifecycleRecurring marks fingerprints present in both snapshots.
	LifecycleRecurring = "recurring"
	// LifecycleResolved marks fingerprints present only in the older snapshot.
	LifecycleResolved = "resolved"
)

// Classify computes the lifecycle of every fingerprint present in either
// snapshot. The older set may be empty (first snapshot): every finding of the
// newer snapshot is new then.
func Classify(older, newer []string) map[string]string {
	olderSet := make(map[string]struct{}, len(older))
	for _, fingerprint := range older {
		olderSet[fingerprint] = struct{}{}
	}
	result := make(map[string]string, len(older)+len(newer))
	for _, fingerprint := range older {
		result[fingerprint] = LifecycleResolved
	}
	for _, fingerprint := range newer {
		if _, found := olderSet[fingerprint]; found {
			result[fingerprint] = LifecycleRecurring
		} else {
			result[fingerprint] = LifecycleNew
		}
	}
	return result
}

// ClassifyFindings is Classify over finding rows. It returns the lifecycle
// per fingerprint plus the resolved findings of the older snapshot (those no
// longer present in the newer one).
func ClassifyFindings(
	older,
	newer []store.FindingSnapshot,
) (map[string]string, []store.FindingSnapshot) {
	lifecycle := Classify(fingerprints(older), fingerprints(newer))
	resolved := make([]store.FindingSnapshot, 0)
	for _, finding := range older {
		if lifecycle[finding.Fingerprint] == LifecycleResolved {
			resolved = append(resolved, finding)
		}
	}
	return lifecycle, resolved
}

func fingerprints(findings []store.FindingSnapshot) []string {
	result := make([]string, 0, len(findings))
	for _, finding := range findings {
		result = append(result, finding.Fingerprint)
	}
	return result
}
