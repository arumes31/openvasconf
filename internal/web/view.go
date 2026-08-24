package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/gmp"
	"openvasconf/internal/networkplan"
	"openvasconf/internal/store"
)

type pageData struct {
	Title            string
	CSRFToken        string
	Authenticated    bool
	Error            string
	Notice           string
	GreenboneVersion string
	GreenboneError   string
	Settings         customer.Settings
	Customers        []customer.Customer
	Events           []store.AuditEvent
	Form             customerForm
	Plan             networkplan.Plan
	Analysis         networkplan.Analysis
	Options          gmp.Options
	Preview          *changePreview
	PreviewToken     string
	ConfirmPath      string
	Query            store.CustomerQuery
	QueryValues      url.Values
	Health           *healthStrip
	Runs             []store.ReconcileRun
	Resources        []store.ManagedResource
	TaskStates       map[string]gmp.TaskStatus
	Operations       operationsView
	Import           *importPreview
	Reports          []store.ReportSnapshot
	Report           *store.ReportSnapshot
	Findings         []store.FindingSnapshot
	FindingRows      []findingView
	PreviousReportID int64
	Trend            []trendView
	Compare          *comparisonView
	ReportFilter     reportFilter
}

type reportFilter struct {
	Customer    string
	Severity    string
	Host        string
	Port        string
	Lifecycle   string
	Disposition string
	Owner       string
	Remediation string
	SLA         string
}

// findingView combines one immutable finding with its lifecycle badge,
// operator annotation, and SLA state for rendering.
type findingView struct {
	store.FindingSnapshot
	Lifecycle        string
	Disposition      string
	Justification    string
	RemediationState string
	RemediationOwner string
	DueDate          *time.Time
	ExpiresAt        *time.Time
	SLADeadline      *time.Time
	SLAState         string
}

// trendView is one severity-trend point with precomputed bar percentages.
type trendView struct {
	Snapshot store.ReportSnapshot
	TotalPct int
	HighPct  int
}

// comparisonView is the A→B snapshot comparison with classified findings.
type comparisonView struct {
	Before    store.ReportSnapshot
	After     store.ReportSnapshot
	New       []store.FindingSnapshot
	Recurring []store.FindingSnapshot
	Resolved  []store.FindingSnapshot
}

type customerForm struct {
	ID           string
	Name         string
	Description  string
	Tags         string
	Networks     string
	ScannerID    string
	ScanConfigID string
	PortListID   string
	Editing      bool
	Schedule     string
	Weekday      int
	Time         string
}

type changePreview struct {
	Mode        string
	Summaries   []string
	Creates     int
	Modifies    int
	Trashes     int
	Unchanged   int
	OutOfPolicy bool
}

type importPreview struct {
	Customers int
	Networks  int
	Creates   int
	Updates   int
}

type operationsView struct {
	Latency     time.Duration    `json:"latency_ns"`
	Feeds       []gmp.Feed       `json:"feeds"`
	Tasks       []gmp.TaskStatus `json:"tasks"`
	ActiveTasks []gmp.TaskStatus `json:"active_tasks"`
	Error       string           `json:"error,omitempty"`
}

func (s *Server) render(
	response http.ResponseWriter,
	request *http.Request,
	name string,
	data pageData,
) {
	data.CSRFToken = csrfToken(request)
	if data.Authenticated && data.Health == nil {
		strip := s.health(request.Context())
		data.Health = &strip
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(response, name, data); err != nil {
		s.logger.Error("template rendering failed", "template", name, "error", err)
	}
}

func formFromCustomer(value customer.Customer) customerForm {
	networks := make([]string, 0, len(value.Networks))
	for _, network := range value.Networks {
		// A range input expands to several rows sharing one Input value.
		if len(networks) > 0 && networks[len(networks)-1] == network.Input {
			continue
		}
		networks = append(networks, network.Input)
	}
	return customerForm{
		ID:           value.ID,
		Name:         value.Name,
		Description:  value.Description,
		Tags:         strings.Join(value.Tags, ", "),
		Networks:     strings.Join(networks, "\n"),
		ScannerID:    value.ScannerID,
		ScanConfigID: value.ScanConfigID,
		PortListID:   value.PortListID,
		Editing:      value.ID != "",
		Weekday:      value.ScheduleWeekday,
		Time:         value.ScheduleTime(),
		Schedule: fmt.Sprintf(
			"%s at %s · %s",
			customer.WeekdayName(value.ScheduleWeekday),
			value.ScheduleTime(),
			value.Timezone,
		),
	}
}
