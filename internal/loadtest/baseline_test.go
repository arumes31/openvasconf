//go:build loadtest

package loadtest

import (
	"strings"
	"testing"

	"openvasconf/internal/networkplan"
)

func TestCompareLoadBaseline(t *testing.T) {
	t.Parallel()

	prior := baseline{
		Scale: scaleMetric{
			Customers:            loadCustomers,
			NetworkInputs:        loadNetworkInputs,
			SnapshotsPerCustomer: loadSnapshotsPerCustomer,
			FindingsPerSnapshot:  loadFindingsPerSnapshot,
		},
		NetworkPlanning:   phaseMetric{AveragePerUnit: 100},
		CustomerCreation:  phaseMetric{AveragePerUnit: 100},
		SnapshotImport:    phaseMetric{AveragePerUnit: 100},
		ComparisonQuery:   phaseMetric{AveragePerUnit: 100},
		ReportPageLatency: phaseMetric{AveragePerUnit: 100},
		MemoryPlanning:    memoryMetric{HeapAllocAfter: 100},
		MemoryImport:      memoryMetric{HeapAllocAfter: 100},
	}
	withinBudget := prior
	withinBudget.NetworkPlanning.AveragePerUnit = 125
	withinBudget.MemoryImport.HeapAllocAfter = 150
	if err := compareLoadBaseline(prior, withinBudget); err != nil {
		t.Fatalf("comparison at tolerance boundary failed: %v", err)
	}

	regressed := prior
	regressed.ComparisonQuery.AveragePerUnit = 126
	err := compareLoadBaseline(prior, regressed)
	if err == nil || !strings.Contains(err.Error(), "comparison query average") {
		t.Fatalf("regression error = %v, want comparison query diagnostic", err)
	}
}

func TestLoadInputsRemainOneCanonicalNetworkEach(t *testing.T) {
	t.Parallel()

	inputs := loadInputs()
	if len(inputs) != loadNetworkInputs {
		t.Fatalf("load inputs = %d, want %d", len(inputs), loadNetworkInputs)
	}
	analysis, err := networkplan.Analyze(networkplan.Input{
		CustomerName: "loadtemplate",
		Networks:     inputs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.CanonicalInputs) != loadNetworkInputs {
		t.Fatalf(
			"canonical load inputs = %d, want %d",
			len(analysis.CanonicalInputs),
			loadNetworkInputs,
		)
	}
}
