package gmp

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// maxRemediationLength caps the normalized remediation summary stored per
// result; longer vendor texts are truncated.
const maxRemediationLength = 2000

// ReportLimits bounds one report fetch. MaxBytes caps the raw XML stream and
// MaxResults caps the number of parsed results; both are enforced while
// streaming so oversized reports fail early.
type ReportLimits struct {
	MaxBytes   int64
	MaxResults int
}

// ReportResult is one normalized result row of a report.
type ReportResult struct {
	ID          string
	Name        string
	NVTOID      string
	NVTName     string
	Host        string
	Port        string
	Location    string
	Threat      string
	Severity    float64
	QOD         int
	CVEs        []string
	Remediation string
}

// ReportDetails is the normalized view of one Greenbone report. The raw
// report XML is streamed, parsed, and discarded; it is never stored.
type ReportDetails struct {
	ID        string
	TaskID    string
	TaskName  string
	Status    string
	Severity  float64
	ScanStart time.Time
	ScanEnd   time.Time
	High      int
	Medium    int
	Low       int
	Log       int
	FalsePos  int
	Results   []ReportResult
}

// Report fetches one report with its results via get_reports and streams the
// response, decoding one result element at a time. The parser tolerates
// missing elements and fails with a clear error when the response exceeds the
// configured byte or result limits.
func (c *Client) Report(
	ctx context.Context,
	reportID string,
	limits ReportLimits,
) (ReportDetails, error) {
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = defaultResponseLimit
	}
	request := struct {
		XMLName  xml.Name `xml:"get_reports"`
		ReportID string   `xml:"report_id,attr"`
		Details  string   `xml:"details,attr"`
		Filter   string   `xml:"filter,attr"`
	}{ReportID: reportID, Details: "1", Filter: "first=1 rows=-1"}

	parser := &reportParser{maxResults: limits.MaxResults}
	if err := c.streamCallWithTimeout(
		ctx,
		request,
		limits.MaxBytes,
		c.reportTimeout,
		parser.consume,
	); err != nil {
		return ReportDetails{}, err
	}
	if !parser.sawResponse {
		return ReportDetails{}, errors.New("gmp: get_reports returned an empty response")
	}
	if err := checkStatus("get_reports", responseStatus{
		Status:     parser.status,
		StatusText: parser.statusText,
	}); err != nil {
		return ReportDetails{}, err
	}
	return parser.details, nil
}

// reportParser walks the get_reports_response token stream. The response
// nests the actual report payload inside an outer report element:
//
//	<get_reports_response status="200">
//	  <report id="...">
//	    <report id="...">
//	      <task id="..."><name>...</name></task>
//	      <scan_start>...</scan_start><scan_end>...</scan_end>
//	      <scan_run_status>Done</scan_run_status><severity>9.8</severity>
//	      <result_count><hole>1</hole>...</result_count>
//	      <results><result id="...">...</result></results>
//	    </report>
//	  </report>
//	</get_reports_response>
//
// Result elements are decoded one at a time; everything else is captured as
// metadata when its path matches the inner report payload.
type reportParser struct {
	maxResults  int
	sawResponse bool
	status      string
	statusText  string
	stack       []string
	details     ReportDetails
}

func (p *reportParser) consume(decoder *xml.Decoder) error {
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "get_reports_response":
				p.sawResponse = true
				for _, attribute := range element.Attr {
					switch attribute.Name.Local {
					case "status":
						p.status = attribute.Value
					case "status_text":
						p.statusText = attribute.Value
					}
				}
			case "report":
				if len(p.stack) == 1 {
					// The outer report element carries the report UUID.
					for _, attribute := range element.Attr {
						if attribute.Name.Local == "id" {
							p.details.ID = attribute.Value
						}
					}
				}
			case "task":
				if p.pathIs("get_reports_response/report/report") {
					for _, attribute := range element.Attr {
						if attribute.Name.Local == "id" {
							p.details.TaskID = attribute.Value
						}
					}
				}
			case "result":
				if p.insideResults() {
					var wire resultWire
					if err := decoder.DecodeElement(&wire, &element); err != nil {
						return fmt.Errorf("gmp: decoding report result: %w", err)
					}
					if err := p.addResult(wire); err != nil {
						return err
					}
					continue
				}
			}
			p.stack = append(p.stack, element.Name.Local)
		case xml.EndElement:
			if len(p.stack) > 0 {
				p.stack = p.stack[:len(p.stack)-1]
			}
			if element.Name.Local == "get_reports_response" {
				return nil
			}
		case xml.CharData:
			p.captureText(string(element))
		}
	}
}

// pathIs reports whether the current element stack equals the given path.
func (p *reportParser) pathIs(path string) bool {
	return strings.Join(p.stack, "/") == path
}

func (p *reportParser) insideResults() bool {
	return len(p.stack) > 0 && p.stack[len(p.stack)-1] == "results"
}

func (p *reportParser) captureText(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	switch strings.Join(p.stack, "/") {
	case "get_reports_response/report/report/task/name":
		p.details.TaskName = text
	case "get_reports_response/report/report/scan_start":
		p.details.ScanStart = parseGMPTime(text)
	case "get_reports_response/report/report/scan_end":
		p.details.ScanEnd = parseGMPTime(text)
	case "get_reports_response/report/report/scan_run_status":
		p.details.Status = text
	case "get_reports_response/report/report/severity":
		p.details.Severity = parseFloat(text)
	case "get_reports_response/report/report/result_count/hole":
		p.details.High = parseInteger(text)
	case "get_reports_response/report/report/result_count/warning":
		p.details.Medium = parseInteger(text)
	case "get_reports_response/report/report/result_count/info":
		p.details.Low = parseInteger(text)
	case "get_reports_response/report/report/result_count/log":
		p.details.Log = parseInteger(text)
	case "get_reports_response/report/report/result_count/false_positive":
		p.details.FalsePos = parseInteger(text)
	}
}

func (p *reportParser) addResult(wire resultWire) error {
	if p.maxResults > 0 && len(p.details.Results) >= p.maxResults {
		return fmt.Errorf(
			"gmp: report exceeds the configured limit of %d results",
			p.maxResults,
		)
	}
	p.details.Results = append(p.details.Results, wire.normalize())
	return nil
}

// resultWire mirrors one report result element. Numeric values stay strings
// on the wire so missing or malformed values do not abort the stream.
type resultWire struct {
	ID       string `xml:"id,attr"`
	Name     string `xml:"name"`
	Host     string `xml:"host"`
	Port     string `xml:"port"`
	Location string `xml:"location"`
	NVT      struct {
		OID        string         `xml:"oid,attr"`
		Name       string         `xml:"name"`
		Tags       string         `xml:"tags"`
		References []nvtReference `xml:"refs>ref"`
	} `xml:"nvt"`
	Threat      string `xml:"threat"`
	Severity    string `xml:"severity"`
	QOD         string `xml:"qod>value"`
	Description string `xml:"description"`
	Solution    struct {
		Text string `xml:",chardata"`
	} `xml:"solution"`
}

type nvtReference struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
}

func (wire resultWire) normalize() ReportResult {
	result := ReportResult{
		ID:          wire.ID,
		Name:        wire.Name,
		NVTOID:      wire.NVT.OID,
		NVTName:     wire.NVT.Name,
		Host:        strings.TrimSpace(wire.Host),
		Port:        wire.Port,
		Location:    wire.Location,
		Threat:      wire.Threat,
		Severity:    parseFloat(wire.Severity),
		QOD:         parseInteger(wire.QOD),
		Remediation: remediation(wire),
	}
	result.CVEs = cveReferences(wire.NVT.Tags, wire.NVT.References)
	return result
}

// remediation prefers the solution text of the NVT tags and falls back to the
// result-level solution element. The summary is capped at
// maxRemediationLength characters.
func remediation(wire resultWire) string {
	value := ""
	if tags := parseNVtTags(wire.NVT.Tags); tags["solution"] != "" {
		value = tags["solution"]
	} else {
		value = strings.TrimSpace(wire.Solution.Text)
	}
	runes := []rune(value)
	if len(runes) > maxRemediationLength {
		value = string(runes[:maxRemediationLength])
	}
	return value
}

// cveReferences merges legacy NVT tag values with current GMP reference IDs.
func cveReferences(tags string, references []nvtReference) []string {
	value := parseNVtTags(tags)["cve"]
	result := make([]string, 0)
	seen := make(map[string]struct{})
	appendCVE := func(value string) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return
		}
		key := strings.ToUpper(trimmed)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		result = append(result, trimmed)
	}
	for _, entry := range strings.Split(value, ",") {
		appendCVE(entry)
	}
	for _, reference := range references {
		if strings.EqualFold(strings.TrimSpace(reference.Type), "cve") {
			appendCVE(reference.ID)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// parseNVtTags splits the pipe-separated key=value NVT tag string.
func parseNVtTags(tags string) map[string]string {
	result := make(map[string]string)
	for _, pair := range strings.Split(tags, "|") {
		key, value, found := strings.Cut(pair, "=")
		if found {
			result[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return result
}

func parseFloat(value string) float64 {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0
	}
	return parsed
}

func parseInteger(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return parsed
}
