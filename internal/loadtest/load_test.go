//go:build loadtest

// Package loadtest implements the reproducible load scenario from the
// reporting design: 500 customers with 2,000 network inputs each, snapshot
// imports, comparison queries, and report-page latency.
//
// Run it with:
//
//	go test -tags loadtest ./internal/loadtest -run TestLoadBaseline -v
//
// The first run writes test-artifacts/loadtest-baseline-<timestamp>.json;
// later runs should compare their metrics against that baseline and only
// tighten budgets with measured evidence. The scenario is deterministic
// (fixed generated inputs) so runs are comparable. Reduce the scale
// constants below only together with a note in the artifact.
package loadtest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"openvasconf/internal/auth"
	"openvasconf/internal/customer"
	"openvasconf/internal/gmp"
	"openvasconf/internal/networkplan"
	"openvasconf/internal/report"
	"openvasconf/internal/store"
	"openvasconf/internal/web"
)

// Scale constants of the scenario. 500 customers × 5 snapshots × 2,000
// findings = 5M finding rows; the full run takes a few minutes on a typical
// dev machine.
const (
	loadCustomers            = 500
	loadNetworkInputs        = 2000
	loadSnapshotsPerCustomer = 5
	loadFindingsPerSnapshot  = 2000
	loadPageSampleCustomers  = 10
	loadAdminPassword        = "loadtest admin password"
)

type phaseMetric struct {
	TotalMilliseconds int64   `json:"total_ms"`
	AveragePerUnit    float64 `json:"avg_ms_per_unit"`
	MaxPerUnit        int64   `json:"max_ms_per_unit,omitempty"`
	Unit              string  `json:"unit"`
}

type memoryMetric struct {
	HeapAllocBefore uint64 `json:"heap_alloc_before_bytes"`
	HeapAllocAfter  uint64 `json:"heap_alloc_after_bytes"`
}

type baseline struct {
	Timestamp         string       `json:"timestamp"`
	Scale             scaleMetric  `json:"scale"`
	NetworkPlanning   phaseMetric  `json:"network_planning"`
	CustomerCreation  phaseMetric  `json:"customer_creation"`
	SnapshotImport    phaseMetric  `json:"snapshot_import"`
	ComparisonQuery   phaseMetric  `json:"comparison_query"`
	ReportPageLatency phaseMetric  `json:"report_page_latency"`
	MemoryPlanning    memoryMetric `json:"memory_planning"`
	MemoryImport      memoryMetric `json:"memory_import"`
}

type scaleMetric struct {
	Customers            int `json:"customers"`
	NetworkInputs        int `json:"network_inputs_per_customer"`
	SnapshotsPerCustomer int `json:"snapshots_per_customer"`
	FindingsPerSnapshot  int `json:"findings_per_snapshot"`
}

func heapAlloc() uint64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// loadInputs builds the deterministic 2,000-entry network input list: 80%
// bare IPs, 10% /30 CIDRs, 10% four-address ranges — all private, so one
// customer stays a single target class below the 4,095-address limit.
func loadInputs() []string {
	inputs := make([]string, 0, loadNetworkInputs)
	for index := range loadNetworkInputs {
		second := (index / 256) % 256
		third := index % 256
		switch index % 10 {
		case 8:
			inputs = append(inputs, fmt.Sprintf("10.1.%d.%d/30", second, third&0xFC))
		case 9:
			inputs = append(inputs, fmt.Sprintf(
				"10.2.%d.%d-10.2.%d.%d",
				second, third&0xFC, second, (third&0xFC)+3,
			))
		default:
			inputs = append(inputs, fmt.Sprintf("10.0.%d.%d", second, index%254+1))
		}
	}
	return inputs
}

func loadFindings(customerIndex, snapshotIndex int) []store.FindingSnapshot {
	findings := make([]store.FindingSnapshot, 0, loadFindingsPerSnapshot)
	for index := range loadFindingsPerSnapshot {
		severity, threat := 0.0, "Log"
		switch index % 10 {
		case 0:
			severity, threat = 9.8, "High"
		case 1, 2:
			severity, threat = 5.0, "Medium"
		case 3, 4, 5:
			severity, threat = 3.0, "Low"
		}
		findings = append(findings, store.FindingSnapshot{
			// The fingerprint ignores the snapshot index, so findings are
			// recurring across snapshots of one customer.
			Fingerprint: fmt.Sprintf("v1:%010d-%010d", customerIndex, index),
			NVTOID:      fmt.Sprintf("1.3.6.1.4.1.25623.1.0.%d", 900000+index%1000),
			Title:       fmt.Sprintf("Load finding %d", index),
			Host:        fmt.Sprintf("10.0.%d.%d", (index/256)%256, index%254+1),
			Port:        "443/tcp",
			Severity:    severity,
			Threat:      threat,
			QOD:         80,
			CVEs:        []string{fmt.Sprintf("CVE-2026-%04d", index%10000)},
		})
	}
	return findings
}

func loadSnapshot(customerID string, customerIndex, snapshotIndex int) store.ReportSnapshot {
	scanEnd := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC).
		Add(time.Duration(snapshotIndex) * 24 * time.Hour)
	return store.ReportSnapshot{
		ReportID:     fmt.Sprintf("load-report-%04d-%d", customerIndex, snapshotIndex),
		TaskID:       fmt.Sprintf("load-task-%04d", customerIndex),
		TaskName:     fmt.Sprintf("loadcust%04d_PrivateIP_Task1", customerIndex),
		CustomerID:   customerID,
		ScanStart:    scanEnd.Add(-time.Hour),
		ScanEnd:      scanEnd,
		Status:       "Done",
		SeverityMax:  9.8,
		CountHigh:    loadFindingsPerSnapshot / 10,
		CountMedium:  loadFindingsPerSnapshot / 5,
		CountLow:     3 * loadFindingsPerSnapshot / 10,
		CountLog:     2 * loadFindingsPerSnapshot / 5,
		FindingCount: loadFindingsPerSnapshot,
	}
}

func TestLoadBaseline(t *testing.T) {
	ctx := context.Background()
	result := baseline{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Scale: scaleMetric{
			Customers:            loadCustomers,
			NetworkInputs:        loadNetworkInputs,
			SnapshotsPerCustomer: loadSnapshotsPerCustomer,
			FindingsPerSnapshot:  loadFindingsPerSnapshot,
		},
	}

	// Phase 1: network normalization and reconciliation planning (pure
	// planning without GMP; the reconciler itself needs a Greenbone socket).
	inputs := loadInputs()
	result.MemoryPlanning.HeapAllocBefore = heapAlloc()
	planningStart := time.Now()
	var planningMax int64
	for index := range loadCustomers {
		start := time.Now()
		plan, err := networkplan.Build(networkplan.Input{
			CustomerName: fmt.Sprintf("loadcust%04d", index),
			Networks:     inputs,
		})
		if err != nil {
			t.Fatalf("networkplan.Build(customer %d) error = %v", index, err)
		}
		if len(plan.Targets) == 0 {
			t.Fatalf("networkplan.Build(customer %d) produced no targets", index)
		}
		if elapsed := time.Since(start).Milliseconds(); elapsed > planningMax {
			planningMax = elapsed
		}
	}
	planningTotal := time.Since(planningStart)
	result.MemoryPlanning.HeapAllocAfter = heapAlloc()
	result.NetworkPlanning = phaseMetric{
		TotalMilliseconds: planningTotal.Milliseconds(),
		AveragePerUnit:    float64(planningTotal.Microseconds()) / 1000.0 / loadCustomers,
		MaxPerUnit:        planningMax,
		Unit:              "customer plan (build-only; reconciler needs GMP)",
	}
	t.Logf("network planning: %v total, %.2f ms/customer", planningTotal, result.NetworkPlanning.AveragePerUnit)

	// Phase 2: customer creation (one persisted network each; the 2,000-input
	// set is exercised in-memory in phase 1 to keep the import phase fast).
	repository, err := store.Open(ctx, filepath.Join(t.TempDir(), "load.db"), "Europe/Vienna")
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = repository.Close() })

	customerIDs := make([]string, 0, loadCustomers)
	creationStart := time.Now()
	for index := range loadCustomers {
		name := fmt.Sprintf("loadcust%04d", index)
		prefix, err := networkplan.Parse(fmt.Sprintf("10.9.%d.1", index%256))
		if err != nil {
			t.Fatalf("networkplan.Parse error = %v", err)
		}
		value := customer.Customer{
			ID:              fmt.Sprintf("load-customer-%04d", index),
			Name:            name,
			SafeName:        name,
			ScheduleWeekday: index%7 + 1,
			ScheduleMinute:  (index * 7) % 1440,
			Timezone:        "Europe/Vienna",
			Networks: []customer.Network{{
				ID:         fmt.Sprintf("load-network-%04d", index),
				CustomerID: fmt.Sprintf("load-customer-%04d", index),
				Input:      prefix.String(),
				Prefix:     prefix.String(),
				Class:      "PrivateIP",
			}},
		}
		if err := repository.CreateCustomer(ctx, value); err != nil {
			t.Fatalf("CreateCustomer(%d) error = %v", index, err)
		}
		customerIDs = append(customerIDs, value.ID)
	}
	creationTotal := time.Since(creationStart)
	result.CustomerCreation = phaseMetric{
		TotalMilliseconds: creationTotal.Milliseconds(),
		AveragePerUnit:    float64(creationTotal.Microseconds()) / 1000.0 / loadCustomers,
		Unit:              "customer",
	}
	t.Logf("customer creation: %v total", creationTotal)

	// Phase 3: snapshot imports into the SQLite store.
	result.MemoryImport.HeapAllocBefore = heapAlloc()
	importStart := time.Now()
	var importMax int64
	for customerIndex, customerID := range customerIDs {
		for snapshotIndex := range loadSnapshotsPerCustomer {
			start := time.Now()
			snapshot := loadSnapshot(customerID, customerIndex, snapshotIndex)
			if err := repository.SaveReportSnapshot(
				ctx,
				snapshot,
				loadFindings(customerIndex, snapshotIndex),
			); err != nil {
				t.Fatalf("SaveReportSnapshot(customer %d, snapshot %d) error = %v", customerIndex, snapshotIndex, err)
			}
			if elapsed := time.Since(start).Milliseconds(); elapsed > importMax {
				importMax = elapsed
			}
		}
	}
	importTotal := time.Since(importStart)
	result.MemoryImport.HeapAllocAfter = heapAlloc()
	snapshotCount := loadCustomers * loadSnapshotsPerCustomer
	result.SnapshotImport = phaseMetric{
		TotalMilliseconds: importTotal.Milliseconds(),
		AveragePerUnit:    float64(importTotal.Microseconds()) / 1000.0 / float64(snapshotCount),
		MaxPerUnit:        importMax,
		Unit:              "snapshot (2000 findings)",
	}
	t.Logf("snapshot import: %v total for %d snapshots", importTotal, snapshotCount)

	// Phase 4: comparison query latency per customer (previous snapshot
	// selection, classification, first-seen grouping).
	comparisonStart := time.Now()
	var comparisonMax int64
	for _, customerID := range customerIDs {
		start := time.Now()
		listed, err := repository.ListReportSnapshots(ctx, customerID, 1)
		if err != nil || len(listed) != 1 {
			t.Fatalf("ListReportSnapshots() = %d, %v", len(listed), err)
		}
		latest := listed[0]
		previous, err := repository.PreviousImportedSnapshot(ctx, latest)
		if err != nil {
			t.Fatalf("PreviousImportedSnapshot() error = %v", err)
		}
		latestFindings, err := repository.ReportFindings(ctx, latest.ID)
		if err != nil {
			t.Fatalf("ReportFindings() error = %v", err)
		}
		previousFindings, err := repository.ReportFindings(ctx, previous.ID)
		if err != nil {
			t.Fatalf("ReportFindings(previous) error = %v", err)
		}
		lifecycle, _ := report.ClassifyFindings(previousFindings, latestFindings)
		fingerprints := make([]string, 0, len(latestFindings))
		for _, finding := range latestFindings {
			fingerprints = append(fingerprints, finding.Fingerprint)
		}
		if _, err := repository.FirstSeen(ctx, customerID, fingerprints); err != nil {
			t.Fatalf("FirstSeen() error = %v", err)
		}
		if len(lifecycle) == 0 {
			t.Fatal("classification produced no lifecycle entries")
		}
		if elapsed := time.Since(start).Milliseconds(); elapsed > comparisonMax {
			comparisonMax = elapsed
		}
	}
	comparisonTotal := time.Since(comparisonStart)
	result.ComparisonQuery = phaseMetric{
		TotalMilliseconds: comparisonTotal.Milliseconds(),
		AveragePerUnit:    float64(comparisonTotal.Microseconds()) / 1000.0 / loadCustomers,
		MaxPerUnit:        comparisonMax,
		Unit:              "customer comparison",
	}
	t.Logf("comparison queries: %v total", comparisonTotal)

	// Phase 5: report detail page latency through the real web server.
	server, client := loadWebApp(t, repository)
	defer server.Close()
	pageStart := time.Now()
	var pageMax int64
	for index := range loadPageSampleCustomers {
		listed, err := repository.ListReportSnapshots(ctx, customerIDs[index], 1)
		if err != nil || len(listed) != 1 {
			t.Fatalf("ListReportSnapshots() error = %v", err)
		}
		start := time.Now()
		response, err := client.Get(server.URL + fmt.Sprintf("/reports/%d", listed[0].ID))
		if err != nil {
			t.Fatalf("GET report detail error = %v", err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatalf("reading report detail error = %v", err)
		}
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "FINDINGS") {
			t.Fatalf("report detail status = %d", response.StatusCode)
		}
		if elapsed := time.Since(start).Milliseconds(); elapsed > pageMax {
			pageMax = elapsed
		}
	}
	pageTotal := time.Since(pageStart)
	result.ReportPageLatency = phaseMetric{
		TotalMilliseconds: pageTotal.Milliseconds(),
		AveragePerUnit:    float64(pageTotal.Microseconds()) / 1000.0 / loadPageSampleCustomers,
		MaxPerUnit:        pageMax,
		Unit:              "detail page render (2000 findings)",
	}
	t.Logf("report page latency: %v total for %d pages", pageTotal, loadPageSampleCustomers)

	artifact := filepath.Join(
		"..", "..", "test-artifacts",
		"loadtest-baseline-"+time.Now().UTC().Format("20060102-150405")+".json",
	)
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatalf("encoding baseline error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		t.Fatalf("creating artifact directory error = %v", err)
	}
	// #nosec G304 -- the artifact path is built from a fixed relative directory.
	if err := os.WriteFile(artifact, encoded, 0o644); err != nil {
		t.Fatalf("writing baseline artifact error = %v", err)
	}
	t.Logf("baseline written to %s", artifact)
}

type loadGreenbone struct{}

func (loadGreenbone) Ping(context.Context) (string, error) { return "22.4-load", nil }

func (loadGreenbone) Options(context.Context) (gmp.Options, error) { return gmp.Options{}, nil }

type loadSyncer struct{}

func (loadSyncer) Trigger() {}

// loadWebApp boots the real web server against the load-test repository and
// logs in once; the returned client carries the session and CSRF cookies.
func loadWebApp(t *testing.T, repository *store.Store) (*httptest.Server, *http.Client) {
	t.Helper()
	ctx := context.Background()
	authenticator := auth.New(repository, time.Hour)
	if err := authenticator.Bootstrap(ctx, loadAdminPassword); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	application, err := web.New(web.Options{
		Repository: repository,
		Auth:       authenticator,
		Greenbone:  loadGreenbone{},
		Syncer:     loadSyncer{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("web.New() error = %v", err)
	}
	server := httptest.NewServer(application.Handler())

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	response, err := client.Get(server.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login error = %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	csrfToken := ""
	for _, cookie := range jar.Cookies(parsed) {
		if cookie.Name == "openvasconf_csrf" {
			csrfToken = cookie.Value
		}
	}
	if csrfToken == "" {
		t.Fatal("csrf cookie missing")
	}
	loginResponse, err := client.PostForm(server.URL+"/login", url.Values{
		"username":   {"admin"},
		"password":   {loadAdminPassword},
		"csrf_token": {csrfToken},
	})
	if err != nil {
		t.Fatalf("POST /login error = %v", err)
	}
	_, _ = io.Copy(io.Discard, loginResponse.Body)
	loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", loginResponse.StatusCode)
	}
	return server, client
}
