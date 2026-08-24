package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"openvasconf/internal/gmp"
	"openvasconf/internal/store"
)

type operationalGreenbone interface {
	Feeds(ctx context.Context) ([]gmp.Feed, error)
	Tasks(ctx context.Context) ([]gmp.TaskStatus, error)
	StartTask(ctx context.Context, taskID string) (string, error)
	StopTask(ctx context.Context, taskID string) error
	InspectResource(ctx context.Context, kind, resourceID string) (gmp.ResourceDetails, error)
}

type driftItem struct {
	Kind     string `json:"kind"`
	Class    string `json:"class,omitempty"`
	Sequence int    `json:"sequence,omitempty"`
	State    string `json:"state"`
	Detail   string `json:"detail"`
}

func (s *Server) operations(ctx context.Context) operationsView {
	started := time.Now()
	_, err := s.greenbone.Ping(ctx)
	result := operationsView{Latency: time.Since(started)}
	if err != nil {
		result.Error = "Greenbone connection failed"
		return result
	}
	operations, ok := s.greenbone.(operationalGreenbone)
	if !ok {
		result.Error = "Operational GMP methods are unavailable"
		return result
	}
	result.Feeds, err = operations.Feeds(ctx)
	if err != nil {
		result.Error = "Feed status unavailable: " + err.Error()
		return result
	}
	result.Tasks, err = operations.Tasks(ctx)
	if err != nil {
		result.Error = "Task status unavailable: " + err.Error()
		return result
	}
	for _, task := range result.Tasks {
		switch strings.ToLower(task.Status) {
		case "running", "requested", "queued", "processing":
			result.ActiveTasks = append(result.ActiveTasks, task)
		}
	}
	return result
}

func (s *Server) apiOperations(response http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 12*time.Second)
	defer cancel()
	result := s.operations(ctx)
	status := http.StatusOK
	if result.Error != "" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(response, status, result)
}

func (s *Server) settingsTest(response http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 12*time.Second)
	defer cancel()
	result := s.operations(ctx)
	if result.Error != "" {
		http.Redirect(response, request, "/settings?connection=failed", http.StatusSeeOther)
		return
	}
	http.Redirect(response, request, "/settings?connection=ok", http.StatusSeeOther)
}

func (s *Server) startScan(response http.ResponseWriter, request *http.Request) {
	task, customerID, ok := s.verifiedTask(response, request)
	if !ok {
		return
	}
	operations, castable := s.greenbone.(operationalGreenbone)
	if !castable {
		http.Error(response, "scan start is unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := operations.StartTask(request.Context(), task.GVMID); err != nil {
		http.Error(response, "Greenbone rejected the scan start", http.StatusBadGateway)
		return
	}
	// #nosec G710 -- customerNoticeURL always returns an encoded same-origin path.
	http.Redirect(response, request, customerNoticeURL(customerID, "scan-started"), http.StatusSeeOther)
}

func (s *Server) stopScan(response http.ResponseWriter, request *http.Request) {
	task, customerID, ok := s.verifiedTask(response, request)
	if !ok {
		return
	}
	operations, castable := s.greenbone.(operationalGreenbone)
	if !castable {
		http.Error(response, "scan stop is unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := operations.StopTask(request.Context(), task.GVMID); err != nil {
		http.Error(response, "Greenbone rejected the scan stop", http.StatusBadGateway)
		return
	}
	// The task state on the page keeps coming from Greenbone polling; the stop
	// is only confirmed once Greenbone reports it.
	// #nosec G710 -- customerNoticeURL always returns an encoded same-origin path.
	http.Redirect(response, request, customerNoticeURL(customerID, "scan-stop-requested"), http.StatusSeeOther)
}

func customerNoticeURL(customerID, notice string) string {
	return (&url.URL{
		Path:     "/customers/" + customerID,
		RawQuery: url.Values{"notice": {notice}}.Encode(),
	}).String()
}

// verifiedTask resolves the addressed managed task and confirms that the
// remote object still carries our ownership marker before any control action.
func (s *Server) verifiedTask(
	response http.ResponseWriter,
	request *http.Request,
) (store.ManagedResource, string, bool) {
	customerID := request.PathValue("id")
	sequence, err := strconv.Atoi(request.PathValue("sequence"))
	if err != nil || request.PathValue("kind") != "task" {
		http.NotFound(response, request)
		return store.ManagedResource{}, "", false
	}
	resources, err := s.repository.ManagedResources(request.Context(), customerID)
	if err != nil {
		s.internalError(response, err)
		return store.ManagedResource{}, "", false
	}
	var task store.ManagedResource
	for _, resource := range resources {
		if resource.Kind == "task" && resource.Class == request.PathValue("class") && resource.Sequence == sequence {
			task = resource
			break
		}
	}
	if task.GVMID == "" || task.State != "applied" {
		http.Error(response, "managed task is not ready", http.StatusConflict)
		return store.ManagedResource{}, "", false
	}
	operations, castable := s.greenbone.(operationalGreenbone)
	if !castable {
		http.Error(response, "task control is unavailable", http.StatusServiceUnavailable)
		return store.ManagedResource{}, "", false
	}
	details, err := operations.InspectResource(request.Context(), "task", task.GVMID)
	if err != nil || !strings.Contains(details.Comment, task.OwnershipMarker) {
		http.Error(response, "task ownership could not be verified", http.StatusConflict)
		return store.ManagedResource{}, "", false
	}
	return task, customerID, true
}

func (s *Server) apiCustomerDrift(response http.ResponseWriter, request *http.Request) {
	customerID := request.PathValue("id")
	if _, err := s.repository.Customer(request.Context(), customerID); errors.Is(err, store.ErrNotFound) {
		writeJSON(response, http.StatusNotFound, map[string]string{"error": "customer not found"})
		return
	} else if err != nil {
		writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "customer unavailable"})
		return
	}
	resources, err := s.repository.ManagedResources(request.Context(), customerID)
	if err != nil {
		writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "managed state unavailable"})
		return
	}
	operations, ok := s.greenbone.(operationalGreenbone)
	if !ok {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "remote inspection unavailable"})
		return
	}
	items := make([]driftItem, 0)
	for _, resource := range resources {
		item := driftItem{Kind: resource.Kind, Class: resource.Class, Sequence: resource.Sequence, State: "in-sync", Detail: "desired, applied, and remote ownership agree"}
		if resource.GVMID == "" {
			item.State, item.Detail = "missing", "no Greenbone object is recorded"
		} else {
			details, inspectErr := operations.InspectResource(request.Context(), resource.Kind, resource.GVMID)
			switch {
			case errors.Is(inspectErr, gmp.ErrNotFound):
				item.State, item.Detail = "missing", "Greenbone object no longer exists"
			case inspectErr != nil:
				item.State, item.Detail = "unknown", "remote inspection failed"
			case !strings.Contains(details.Comment, resource.OwnershipMarker):
				item.State, item.Detail = "ownership-mismatch", "remote ownership marker differs"
			case resource.State != "applied":
				item.State, item.Detail = "pending", fmt.Sprintf("local applied state is %s", resource.State)
			}
		}
		items = append(items, item)
	}
	writeJSON(response, http.StatusOK, map[string]any{"customer_id": customerID, "resources": items, "checked_at": time.Now().UTC()})
}
