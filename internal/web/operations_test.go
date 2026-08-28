package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"openvasconf/internal/gmp"
)

type operationsGreenbone struct {
	fakeGreenbone
	pingErr  error
	feedsErr error
	tasksErr error
	feeds    []gmp.Feed
	tasks    []gmp.TaskStatus
}

func (f operationsGreenbone) Ping(context.Context) (string, error) {
	return "test", f.pingErr
}

func (f operationsGreenbone) Feeds(context.Context) ([]gmp.Feed, error) {
	return f.feeds, f.feedsErr
}

func (f operationsGreenbone) Tasks(context.Context) ([]gmp.TaskStatus, error) {
	return f.tasks, f.tasksErr
}

func (f operationsGreenbone) StartTask(context.Context, string) (string, error) {
	return "report", nil
}

func (f operationsGreenbone) StopTask(context.Context, string) error {
	return nil
}

func (f operationsGreenbone) InspectResource(context.Context, string, string) (gmp.ResourceDetails, error) {
	return gmp.ResourceDetails{}, nil
}

func TestOperationsSummarizesGreenboneState(t *testing.T) {
	t.Parallel()

	server := &Server{greenbone: operationsGreenbone{
		feeds: []gmp.Feed{{Type: "NVT", Name: "feed"}},
		tasks: []gmp.TaskStatus{
			{ID: "running", Status: "Running"},
			{ID: "queued", Status: "queued"},
			{ID: "done", Status: "Done"},
		},
	}}
	result := server.operations(t.Context())
	if result.Error != "" || len(result.Feeds) != 1 || len(result.ActiveTasks) != 2 {
		t.Fatalf("operations = %#v", result)
	}
}

func TestOperationsReportsDependencyErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		greenbone Greenbone
		contains  string
	}{
		{name: "ping", greenbone: operationsGreenbone{pingErr: errors.New("offline")}, contains: "connection failed"},
		{name: "unsupported", greenbone: fakeGreenbone{}, contains: "unavailable"},
		{name: "feeds", greenbone: operationsGreenbone{feedsErr: errors.New("feed error")}, contains: "Feed status unavailable"},
		{name: "tasks", greenbone: operationsGreenbone{tasksErr: errors.New("task error")}, contains: "Task status unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := (&Server{greenbone: test.greenbone}).operations(t.Context())
			if !strings.Contains(result.Error, test.contains) {
				t.Errorf("error = %q, want substring %q", result.Error, test.contains)
			}
		})
	}
}

func TestOperationsAPI(t *testing.T) {
	greenbone := &fakeTaskControlGreenbone{
		fakeGreenbone: fakeGreenbone{options: testOptions()},
		tasks:         []gmp.TaskStatus{{ID: "task", Status: "Running"}},
		comments:      map[string]string{},
	}
	app := newTaskControlApp(t, greenbone)
	login(t, app)
	response, err := app.client.Get(app.server.URL + "/api/operations")
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, response); response.StatusCode != http.StatusOK || !strings.Contains(body, `"active_tasks"`) {
		t.Fatalf("operations API response = %d: %s", response.StatusCode, body)
	}
}
