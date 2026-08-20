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
	Runs             []store.ReconcileRun
	Resources        []store.ManagedResource
	TaskStates       map[string]gmp.TaskStatus
	Operations       operationsView
	Import           *importPreview
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
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(response, name, data); err != nil {
		s.logger.Error("template rendering failed", "template", name, "error", err)
	}
}

func formFromCustomer(value customer.Customer) customerForm {
	networks := make([]string, 0, len(value.Networks))
	for _, network := range value.Networks {
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
