package gmp

import (
	"strings"
	"testing"
)

func TestManagedTasksConfigureThreeReportRetention(t *testing.T) {
	for _, modify := range []bool{false, true} {
		requests := make(chan observedRequest, 1)
		response := `<create_task_response status="201" id="task-1"/>`
		if modify {
			response = `<modify_task_response status="200"/>`
		}
		client := fakeClient(t, []string{response}, requests)
		value := Task{Name: "managed"}
		if modify {
			if err := client.ModifyTask(t.Context(), "task-1", value); err != nil {
				t.Fatal(err)
			}
		} else if _, err := client.CreateTask(t.Context(), value); err != nil {
			t.Fatal(err)
		}
		request := <-requests
		for _, want := range []string{"<scanner_name>auto_delete</scanner_name><value>keep</value>", "<scanner_name>auto_delete_data</scanner_name><value>3</value>"} {
			if !strings.Contains(request.XML, want) {
				t.Fatalf("retention missing from %s: %s", request.Name, request.XML)
			}
		}
	}
}

func TestExistingTaskRetentionChangesPreferencesOnly(t *testing.T) {
	requests := make(chan observedRequest, 2)
	client := fakeClient(t, []string{`<get_tasks_response status="200"><task id="task-1"><preferences><preference><scanner_name>auto_delete</scanner_name><value>0</value></preference></preferences></task></get_tasks_response>`, `<modify_task_response status="200"/>`}, requests)
	if err := client.EnsureTaskReportRetention(t.Context(), "task-1"); err != nil {
		t.Fatal(err)
	}
	<-requests
	request := <-requests
	if request.Name != "modify_task" || strings.Contains(request.XML, "<target") || strings.Contains(request.XML, "<config") || strings.Contains(request.XML, "<schedule") || !strings.Contains(request.XML, "<value>3</value>") {
		t.Fatalf("unsafe retention update: %s", request.XML)
	}
}

func TestExistingTaskWithRetentionNeedsNoMutation(t *testing.T) {
	requests := make(chan observedRequest, 1)
	client := fakeClient(t, []string{`<get_tasks_response status="200"><task id="task-1"><preferences><preference><scanner_name>auto_delete</scanner_name><value>keep</value></preference><preference><scanner_name>auto_delete_data</scanner_name><value>3</value></preference></preferences></task></get_tasks_response>`}, requests)
	if err := client.EnsureTaskReportRetention(t.Context(), "task-1"); err != nil {
		t.Fatal(err)
	}
	request := <-requests
	if request.Name != "get_tasks" || !strings.Contains(request.XML, `details="1"`) {
		t.Fatalf("retention check: %s", request.XML)
	}
}
