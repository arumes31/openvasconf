package gmp

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestClientFeeds(t *testing.T) {
	t.Parallel()

	client := fakeClient(t, []string{`<get_feeds_response status="200" status_text="OK">
		<feed><type>NVT</type><name>Greenbone Community Feed</name><version>20260828</version>
		<description>Vulnerability tests</description><currently_syncing>true</currently_syncing>
		<timestamp>2026-08-28T10:11:12Z</timestamp></feed>
		<feed><type>SCAP</type><name>SCAP</name><currently_syncing>0</currently_syncing><timestamp>invalid</timestamp></feed>
		</get_feeds_response>`}, nil)
	feeds, err := client.Feeds(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(feeds) != 2 || !feeds[0].CurrentlySyncing || feeds[0].UpdatedAt.IsZero() || feeds[1].CurrentlySyncing || !feeds[1].UpdatedAt.IsZero() {
		t.Fatalf("feeds = %#v", feeds)
	}
}

func TestClientTasksParsesStatusAndLastReport(t *testing.T) {
	t.Parallel()

	client := fakeClient(t, []string{`<get_tasks_response status="200" status_text="OK">
		<task id="task-1"><name>managed task</name><comment>owned</comment><status>Running</status><progress>42</progress>
		<target id="target-1"/><config id="config-1"/><scanner id="scanner-1"/><schedule id="schedule-1"/>
		<last_report><report id="report-1"><scan_run_status>Done</scan_run_status><severity>8.1</severity>
		<scan_start>2026-08-28 10:00:00</scan_start><scan_end>2026-08-28T10:30:00Z</scan_end>
		<result_count><hole>2</hole><warning>3</warning><info>4</info><log>5</log><false_positive>1</false_positive></result_count>
		</report></last_report></task></get_tasks_response>`}, nil)
	tasks, err := client.Tasks(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].TargetID != "target-1" || tasks[0].LastReport == nil {
		t.Fatalf("tasks = %#v", tasks)
	}
	report := tasks[0].LastReport
	if report.High != 2 || report.Medium != 3 || report.Low != 4 || report.Log != 5 || report.FalsePos != 1 || report.ScanStart.IsZero() {
		t.Errorf("last report = %#v", report)
	}
}

func TestClientStartsAndStopsTask(t *testing.T) {
	t.Parallel()

	requests := make(chan observedRequest, 1)
	client := fakeClient(t, []string{`<start_task_response status="202" status_text="OK"><report_id>report-1</report_id></start_task_response>`}, requests)
	reportID, err := client.StartTask(t.Context(), "task-1")
	if err != nil || reportID != "report-1" {
		t.Fatalf("StartTask() = %q, %v", reportID, err)
	}
	if request := <-requests; request.Name != "start_task" || !strings.Contains(request.XML, `task_id="task-1"`) {
		t.Errorf("start request = %#v", request)
	}

	client = fakeClient(t, []string{`<stop_task_response status="200" status_text="OK"/>`}, nil)
	if err := client.StopTask(t.Context(), "task-1"); err != nil {
		t.Fatalf("StopTask() error = %v", err)
	}
}

func TestClientInspectsResources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		kind     string
		response string
		check    func(ResourceDetails) bool
	}{
		{name: "schedule", kind: "schedule", response: `<get_schedules_response status="200" status_text="OK"><schedule id="schedule-1"><name>weekly</name><comment>owned</comment><icalendar>BEGIN:VCALENDAR</icalendar><timezone>Europe/Vienna</timezone></schedule></get_schedules_response>`, check: func(value ResourceDetails) bool { return value.ID == "schedule-1" && value.Timezone == "Europe/Vienna" }},
		{name: "target", kind: "target", response: `<get_targets_response status="200" status_text="OK"><target id="target-1"><name>target</name><comment>owned</comment><hosts>10.0.0.1, 10.0.0.2</hosts><port_list id="ports-1"/></target></get_targets_response>`, check: func(value ResourceDetails) bool { return len(value.Hosts) == 2 && value.PortListID == "ports-1" }},
		{name: "task", kind: "task", response: `<get_tasks_response status="200" status_text="OK"><task id="task-1"><name>task</name><comment>owned</comment><status>Done</status><target id="target-1"/><config id="config-1"/><scanner id="scanner-1"/><schedule id="schedule-1"/></task></get_tasks_response>`, check: func(value ResourceDetails) bool {
			return value.ID == "task-1" && value.ConfigID == "config-1" && value.Status == "Done"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fakeClient(t, []string{test.response}, nil)
			value, err := client.InspectResource(t.Context(), test.kind, test.kind+"-1")
			if err != nil {
				t.Fatal(err)
			}
			if !test.check(value) {
				t.Errorf("resource = %#v", value)
			}
		})
	}
}

func TestClientInspectResourceErrors(t *testing.T) {
	t.Parallel()

	if _, err := (&Client{}).InspectResource(t.Context(), "unsupported", "id"); err == nil {
		t.Fatal("InspectResource(unsupported) error = nil")
	}
	for _, kind := range []string{"schedule", "target", "task"} {
		t.Run(kind+" missing", func(t *testing.T) {
			command, _, _, err := resourceQuery(kind)
			if err != nil {
				t.Fatal(err)
			}
			response := `<` + command + `_response status="200" status_text="OK"></` + command + `_response>`
			client := fakeClient(t, []string{response}, nil)
			_, err = client.InspectResource(t.Context(), kind, "missing")
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("error = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestOperationParsingHelpers(t *testing.T) {
	t.Parallel()

	if hosts := splitHosts(" 10.0.0.1,10.0.0.2 "); len(hosts) != 2 || hosts[1] != "10.0.0.2" {
		t.Errorf("splitHosts() = %#v", hosts)
	}
	if hosts := splitHosts("   "); len(hosts) != 0 {
		t.Errorf("splitHosts(empty) = %#v", hosts)
	}
	if got := parseGMPTime("2026-08-28T10:00:00Z"); got.Equal(time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)) == false {
		t.Errorf("parseGMPTime() = %v", got)
	}
	if got := parseGMPTime("invalid"); !got.IsZero() {
		t.Errorf("parseGMPTime(invalid) = %v", got)
	}
}
