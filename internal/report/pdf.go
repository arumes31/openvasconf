package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// Minimal hand-rolled PDF writer: Helvetica base fonts, text-only pages,
// classic xref table. The summary report is deliberately concise — it is not
// a recreation of the Greenbone report.

const (
	pdfPageWidth    = 595
	pdfPageHeight   = 842
	pdfMargin       = 50
	pdfLineHeight   = 13
	pdfMaxFindings  = 50
	pdfTitleMaxWide = 62
)

// pdfDocument collects indirect objects and renders them with a consistent
// xref table.
type pdfDocument struct {
	objects [][]byte
}

func (d *pdfDocument) add(body []byte) int {
	d.objects = append(d.objects, body)
	return len(d.objects)
}

func (d *pdfDocument) set(number int, body []byte) {
	d.objects[number-1] = body
}

func (d *pdfDocument) render(w io.Writer, root int) error {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(d.objects)+1)
	for index, body := range d.objects {
		offsets[index+1] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n", index+1)
		buf.Write(body)
		buf.WriteString("\nendobj\n")
	}
	xrefStart := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(d.objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for index := 1; index <= len(d.objects); index++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[index])
	}
	fmt.Fprintf(
		&buf,
		"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(d.objects)+1,
		root,
		xrefStart,
	)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("report: writing pdf: %w", err)
	}
	return nil
}

// pdfCanvas accumulates text operators for one page.
type pdfCanvas struct {
	buf bytes.Buffer
	y   float64
}

func (c *pdfCanvas) line(x, size float64, font, value string) {
	fmt.Fprintf(&c.buf, "BT /%s %.1f Tf %.1f %.1f Td (%s) Tj ET\n", font, size, x, c.y, pdfEscape(value))
	c.y -= pdfLineHeight
}

func pdfEscape(value string) string {
	ascii := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return '?'
		}
		return r
	}, value)
	ascii = strings.ReplaceAll(ascii, `\`, `\\`)
	ascii = strings.ReplaceAll(ascii, `(`, `\(`)
	ascii = strings.ReplaceAll(ascii, `)`, `\)`)
	return ascii
}

func pdfTruncate(value string, max int) string {
	runes := []rune(value)
	if len(runes) > max {
		return string(runes[:max-1]) + "~"
	}
	return value
}

// WritePDFExport writes a concise one-or-few-page summary: title block,
// severity distribution, lifecycle/disposition/SLA counts, and the top
// findings (capped at pdfMaxFindings).
func WritePDFExport(w io.Writer, meta ExportMeta, rows []ExportRow) error {
	canvas := newPDFCanvas()
	canvas.line(pdfMargin, 16, "F2", "Scan report summary")
	canvas.gap(6)
	canvas.line(pdfMargin, 10, "F1", "Customer:  "+pdfValue(meta.CustomerName, "unmapped"))
	canvas.line(pdfMargin, 10, "F1", "Task:      "+meta.TaskName)
	canvas.line(pdfMargin, 10, "F1", "Report ID: "+meta.ReportID)
	canvas.line(pdfMargin, 10, "F1", "Scan:      "+pdfScanWindow(meta))
	canvas.line(pdfMargin, 10, "F1", "Exported:  "+meta.ExportedAt.UTC().Format("2006-01-02 15:04 UTC"))
	if meta.Truncated {
		canvas.line(pdfMargin, 10, "F2", "TRUNCATED: export row limit reached; counts cover exported rows only.")
	}
	canvas.gap(8)

	counts := pdfCounts(rows)
	canvas.line(pdfMargin, 12, "F2", "Severity distribution")
	canvas.line(pdfMargin, 10, "F1", fmt.Sprintf(
		"High %d    Medium %d    Low %d    Log %d    False positive %d",
		counts.high, counts.medium, counts.low, counts.log, counts.falsePositive,
	))
	canvas.gap(6)
	canvas.line(pdfMargin, 12, "F2", "Lifecycle / dispositions / SLA")
	canvas.line(pdfMargin, 10, "F1", fmt.Sprintf(
		"New %d    Recurring %d", counts.lifecycleNew, counts.recurring,
	))
	canvas.line(pdfMargin, 10, "F1", fmt.Sprintf(
		"Active %d    False positive %d    Accepted risk %d",
		counts.active, counts.fpDisposition, counts.acceptedRisk,
	))
	canvas.line(pdfMargin, 10, "F1", fmt.Sprintf(
		"On track %d    Due soon %d    Overdue %d    No SLA %d",
		counts.onTrack, counts.dueSoon, counts.overdue, counts.noSLA,
	))
	canvas.gap(8)

	canvas.line(pdfMargin, 12, "F2", fmt.Sprintf("Top findings (max %d, most severe first)", pdfMaxFindings))
	header := fmt.Sprintf("%-6s %-16s %-9s %s", "SEV", "HOST", "PORT", "FINDING")
	canvas.line(pdfMargin, 9, "F2", header)
	shown := 0
	for _, row := range rows {
		if shown >= pdfMaxFindings {
			break
		}
		if canvas.nearBottom() {
			canvas = canvas.nextPage()
			canvas.line(pdfMargin, 9, "F2", header)
		}
		canvas.line(pdfMargin, 9, "F1", fmt.Sprintf(
			"%-6.1f %-16s %-9s %s",
			row.Severity,
			pdfTruncate(row.Host, 16),
			pdfTruncate(row.Port, 9),
			pdfTruncate(row.Title, pdfTitleMaxWide),
		))
		shown++
	}
	if len(rows) > shown {
		canvas.line(pdfMargin, 9, "F1", fmt.Sprintf("... and %d more findings not shown.", len(rows)-shown))
	}

	return canvas.document(w)
}

func pdfValue(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func pdfScanWindow(meta ExportMeta) string {
	start, end := "unknown", "unknown"
	if !meta.ScanStart.IsZero() {
		start = meta.ScanStart.Format("2006-01-02 15:04")
	}
	if !meta.ScanEnd.IsZero() {
		end = meta.ScanEnd.Format("2006-01-02 15:04")
	}
	return start + " -> " + end
}

type pdfCountSummary struct {
	high, medium, low, log, falsePositive int
	lifecycleNew, recurring               int
	active, fpDisposition, acceptedRisk   int
	onTrack, dueSoon, overdue, noSLA      int
}

func pdfCounts(rows []ExportRow) pdfCountSummary {
	var counts pdfCountSummary
	for _, row := range rows {
		switch severityClassOfThreat(row.Threat) {
		case "high":
			counts.high++
		case "medium":
			counts.medium++
		case "low":
			counts.low++
		case "false_positive":
			counts.falsePositive++
		default:
			counts.log++
		}
		switch row.Lifecycle {
		case LifecycleNew:
			counts.lifecycleNew++
		case LifecycleRecurring:
			counts.recurring++
		}
		switch row.Disposition {
		case "false_positive":
			counts.fpDisposition++
		case "accepted_risk":
			counts.acceptedRisk++
		default:
			counts.active++
		}
		switch row.SLAState {
		case SLAStateOnTrack:
			counts.onTrack++
		case SLAStateDueSoon:
			counts.dueSoon++
		case SLAStateOverdue:
			counts.overdue++
		default:
			counts.noSLA++
		}
	}
	return counts
}

// severityClassOfThreat mirrors the threat classification used for display.
func severityClassOfThreat(threat string) string {
	switch strings.ToLower(strings.ReplaceAll(threat, " ", "_")) {
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "false_positive":
		return "false_positive"
	default:
		return "log"
	}
}

// pdfPagination tracks the open pages of the summary.
type pdfPagination struct {
	pages []*pdfCanvas
}

func newPDFCanvas() *pdfPagination {
	pagination := &pdfPagination{}
	pagination.nextPage()
	return pagination
}

func (p *pdfPagination) current() *pdfCanvas {
	return p.pages[len(p.pages)-1]
}

func (p *pdfPagination) nextPage() *pdfPagination {
	p.pages = append(p.pages, &pdfCanvas{y: pdfPageHeight - pdfMargin})
	return p
}

// Proxy line/y access to the current page so the composition code reads
// naturally.
func (p *pdfPagination) line(x, size float64, font, value string) {
	p.current().line(x, size, font, value)
}

func (p *pdfPagination) gap(points float64) {
	p.current().y -= points
}

func (p *pdfPagination) nearBottom() bool {
	return p.current().y < pdfMargin+2*pdfLineHeight
}

func (p *pdfPagination) document(w io.Writer) error {
	doc := &pdfDocument{}
	catalog := doc.add(nil)
	pagesRef := doc.add(nil)
	fontRegular := doc.add([]byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))
	fontBold := doc.add([]byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"))

	pageRefs := make([]string, 0, len(p.pages))
	for _, canvas := range p.pages {
		content := canvas.buf.Bytes()
		contentRef := doc.add([]byte(fmt.Sprintf(
			"<< /Length %d >>\nstream\n%sendstream",
			len(content),
			content,
		)))
		pageRef := doc.add([]byte(fmt.Sprintf(
			"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %d %d] "+
				"/Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> /Contents %d 0 R >>",
			pagesRef,
			pdfPageWidth,
			pdfPageHeight,
			fontRegular,
			fontBold,
			contentRef,
		)))
		pageRefs = append(pageRefs, fmt.Sprintf("%d 0 R", pageRef))
	}
	doc.set(catalog, []byte(fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pagesRef)))
	doc.set(pagesRef, []byte(fmt.Sprintf(
		"<< /Type /Pages /Kids [%s] /Count %d >>",
		strings.Join(pageRefs, " "),
		len(pageRefs),
	)))
	return doc.render(w, catalog)
}
