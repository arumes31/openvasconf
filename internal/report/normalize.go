package report

import (
	"openvasconf/internal/gmp"
	"openvasconf/internal/store"
)

// Normalize maps a parsed Greenbone report to a report snapshot and its
// findings. Finding fingerprints are derived from the customer and the
// finding identity. Severity totals and the maximum severity are computed
// from the findings; when a report carries no result details (for example a
// log-only report) the GMP-provided counts are used as a fallback.
func Normalize(
	customerID string,
	report gmp.ReportDetails,
) (store.ReportSnapshot, []store.FindingSnapshot) {
	snapshot := store.ReportSnapshot{
		ReportID:   report.ID,
		TaskID:     report.TaskID,
		TaskName:   report.TaskName,
		CustomerID: customerID,
		ScanStart:  report.ScanStart,
		ScanEnd:    report.ScanEnd,
		Status:     report.Status,
	}
	findings := make([]store.FindingSnapshot, 0, len(report.Results))
	maxSeverity := 0.0
	for _, result := range report.Results {
		threat := threatOf(result)
		findings = append(findings, store.FindingSnapshot{
			Fingerprint: Fingerprint(
				customerID,
				result.NVTOID,
				result.Host,
				result.Port,
				result.Location,
			),
			NVTOID:       result.NVTOID,
			Title:        findingTitle(result),
			Host:         result.Host,
			Port:         result.Port,
			Location:     result.Location,
			Severity:     result.Severity,
			Threat:       threat,
			QOD:          result.QOD,
			CVEs:         result.CVEs,
			Remediation:  result.Remediation,
			Evidence:     result.Evidence,
			CVSSVector:   result.CVSSVector,
			Summary:      result.Summary,
			Insight:      result.Insight,
			Impact:       result.Impact,
			Affected:     result.Affected,
			SolutionType: result.SolutionType,
			References:   result.References,
		})
		switch threat {
		case "High":
			snapshot.CountHigh++
		case "Medium":
			snapshot.CountMedium++
		case "Low":
			snapshot.CountLow++
		case "False Positive":
			snapshot.CountFalsePos++
		default:
			snapshot.CountLog++
		}
		if result.Severity > maxSeverity {
			maxSeverity = result.Severity
		}
	}
	snapshot.FindingCount = len(findings)
	if len(findings) == 0 {
		snapshot.CountHigh = report.High
		snapshot.CountMedium = report.Medium
		snapshot.CountLow = report.Low
		snapshot.CountLog = report.Log
		snapshot.CountFalsePos = report.FalsePos
		snapshot.FindingCount = report.High + report.Medium + report.Low +
			report.Log + report.FalsePos
		maxSeverity = report.Severity
	}
	snapshot.SeverityMax = maxSeverity
	return snapshot, findings
}

// threatOf normalizes the GMP threat class and derives one from the severity
// score when the report omits it.
func threatOf(result gmp.ReportResult) string {
	switch result.Threat {
	case "High", "Medium", "Low", "Log", "False Positive":
		return result.Threat
	}
	switch {
	case result.Severity >= 7.0:
		return "High"
	case result.Severity >= 4.0:
		return "Medium"
	case result.Severity > 0:
		return "Low"
	default:
		return "Log"
	}
}

func findingTitle(result gmp.ReportResult) string {
	if result.NVTName != "" {
		return result.NVTName
	}
	return result.Name
}
