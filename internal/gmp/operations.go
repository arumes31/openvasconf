package gmp

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Feed struct {
	Type             string    `json:"type"`
	Name             string    `json:"name"`
	Version          string    `json:"version"`
	Description      string    `json:"description,omitempty"`
	CurrentlySyncing bool      `json:"currently_syncing"`
	UpdatedAt        time.Time `json:"updated_at,omitempty"`
}

type TaskStatus struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Comment    string        `json:"-"`
	Status     string        `json:"status"`
	Progress   int           `json:"progress"`
	TargetID   string        `json:"target_id"`
	ConfigID   string        `json:"config_id"`
	ScannerID  string        `json:"scanner_id"`
	ScheduleID string        `json:"schedule_id"`
	LastReport *ReportStatus `json:"last_report,omitempty"`
}

type ReportStatus struct {
	ID        string    `json:"id"`
	Status    string    `json:"status,omitempty"`
	Severity  float64   `json:"severity"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	Low       int       `json:"low"`
	Log       int       `json:"log"`
	FalsePos  int       `json:"false_positive"`
	ScanStart time.Time `json:"scan_start,omitempty"`
	ScanEnd   time.Time `json:"scan_end,omitempty"`
}

type ResourceDetails struct {
	ID         string
	Name       string
	Comment    string
	Hosts      []string
	PortListID string
	ConfigID   string
	TargetID   string
	ScannerID  string
	ScheduleID string
	ICalendar  string
	Timezone   string
	Status     string
}

func (c *Client) Feeds(ctx context.Context) ([]Feed, error) {
	request := struct {
		XMLName xml.Name `xml:"get_feeds"`
	}{}
	var response struct {
		responseStatus
		Feeds []struct {
			Type             string `xml:"type"`
			Name             string `xml:"name"`
			Version          string `xml:"version"`
			Description      string `xml:"description"`
			CurrentlySyncing string `xml:"currently_syncing"`
			Timestamp        string `xml:"timestamp"`
		} `xml:"feed"`
	}
	if err := c.call(ctx, request, &response); err != nil {
		return nil, err
	}
	if err := checkStatus("get_feeds", response.responseStatus); err != nil {
		return nil, err
	}
	feeds := make([]Feed, 0, len(response.Feeds))
	for _, item := range response.Feeds {
		feed := Feed{
			Type:             item.Type,
			Name:             item.Name,
			Version:          item.Version,
			Description:      item.Description,
			CurrentlySyncing: item.CurrentlySyncing == "1" || strings.EqualFold(item.CurrentlySyncing, "true"),
		}
		feed.UpdatedAt = parseGMPTime(item.Timestamp)
		feeds = append(feeds, feed)
	}
	return feeds, nil
}

func (c *Client) Tasks(ctx context.Context) ([]TaskStatus, error) {
	result := make([]TaskStatus, 0)
	for page := range maxListPages {
		first := page*listPageSize + 1
		request := listRequest{
			XMLName: xml.Name{Local: "get_tasks"},
			Filter:  "first=" + strconv.Itoa(first) + " rows=" + strconv.Itoa(listPageSize),
		}
		var response taskListResponse
		if err := c.call(ctx, request, &response); err != nil {
			return nil, err
		}
		if err := checkStatus("get_tasks", response.responseStatus); err != nil {
			return nil, err
		}
		for _, item := range response.Tasks {
			result = append(result, taskStatus(item))
		}
		if len(response.Tasks) < listPageSize {
			return result, nil
		}
	}
	return nil, fmt.Errorf(
		"gmp: get_tasks exceeded pagination safety limit of %d resources",
		listPageSize*maxListPages,
	)
}

func (c *Client) StartTask(ctx context.Context, taskID string) (string, error) {
	request := struct {
		XMLName xml.Name `xml:"start_task"`
		TaskID  string   `xml:"task_id,attr"`
	}{TaskID: taskID}
	var response struct {
		responseStatus
		ReportID string `xml:"report_id"`
	}
	if err := c.call(ctx, request, &response); err != nil {
		return "", err
	}
	if err := checkStatus("start_task", response.responseStatus); err != nil {
		return "", err
	}
	return response.ReportID, nil
}

func (c *Client) InspectResource(
	ctx context.Context,
	kind,
	resourceID string,
) (ResourceDetails, error) {
	command, idAttribute, _, err := resourceQuery(kind)
	if err != nil {
		return ResourceDetails{}, err
	}
	request := getResourceRequest{
		XMLName:     xml.Name{Local: command},
		IDAttribute: idAttribute,
		ResourceID:  resourceID,
	}
	switch kind {
	case "schedule":
		var response scheduleDetailsResponse
		if err := c.call(ctx, request, &response); err != nil {
			return ResourceDetails{}, err
		}
		if err := checkStatus(command, response.responseStatus); err != nil {
			return ResourceDetails{}, err
		}
		if len(response.Items) == 0 {
			return ResourceDetails{}, ErrNotFound
		}
		item := response.Items[0]
		return ResourceDetails{ID: item.ID, Name: item.Name, Comment: item.Comment, ICalendar: item.ICalendar, Timezone: item.Timezone}, nil
	case "target":
		var response targetDetailsResponse
		if err := c.call(ctx, request, &response); err != nil {
			return ResourceDetails{}, err
		}
		if err := checkStatus(command, response.responseStatus); err != nil {
			return ResourceDetails{}, err
		}
		if len(response.Items) == 0 {
			return ResourceDetails{}, ErrNotFound
		}
		item := response.Items[0]
		return ResourceDetails{ID: item.ID, Name: item.Name, Comment: item.Comment, Hosts: splitHosts(item.Hosts), PortListID: item.PortList.ID}, nil
	case "task":
		var response taskListResponse
		if err := c.call(ctx, request, &response); err != nil {
			return ResourceDetails{}, err
		}
		if err := checkStatus(command, response.responseStatus); err != nil {
			return ResourceDetails{}, err
		}
		if len(response.Tasks) == 0 {
			return ResourceDetails{}, ErrNotFound
		}
		item := response.Tasks[0]
		return ResourceDetails{ID: item.ID, Name: item.Name, Comment: item.Comment, Status: item.Status, TargetID: item.Target.ID, ConfigID: item.Config.ID, ScannerID: item.Scanner.ID, ScheduleID: item.Schedule.ID}, nil
	default:
		return ResourceDetails{}, fmt.Errorf("gmp: unsupported resource kind %q", kind)
	}
}

type namedReference struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

type taskWire struct {
	ID         string         `xml:"id,attr"`
	Name       string         `xml:"name"`
	Comment    string         `xml:"comment"`
	Status     string         `xml:"status"`
	Progress   int            `xml:"progress"`
	Target     namedReference `xml:"target"`
	Config     namedReference `xml:"config"`
	Scanner    namedReference `xml:"scanner"`
	Schedule   namedReference `xml:"schedule"`
	LastReport struct {
		Report reportWire `xml:"report"`
	} `xml:"last_report"`
}

type reportWire struct {
	ID          string  `xml:"id,attr"`
	Status      string  `xml:"scan_run_status"`
	Severity    float64 `xml:"severity"`
	ScanStart   string  `xml:"scan_start"`
	ScanEnd     string  `xml:"scan_end"`
	ResultCount struct {
		High     int `xml:"hole"`
		Medium   int `xml:"warning"`
		Low      int `xml:"info"`
		Log      int `xml:"log"`
		FalsePos int `xml:"false_positive"`
	} `xml:"result_count"`
}

type taskListResponse struct {
	responseStatus
	Tasks []taskWire `xml:"task"`
}

type scheduleDetailsResponse struct {
	responseStatus
	Items []struct {
		ID        string `xml:"id,attr"`
		Name      string `xml:"name"`
		Comment   string `xml:"comment"`
		ICalendar string `xml:"icalendar"`
		Timezone  string `xml:"timezone"`
	} `xml:"schedule"`
}

type targetDetailsResponse struct {
	responseStatus
	Items []struct {
		ID       string         `xml:"id,attr"`
		Name     string         `xml:"name"`
		Comment  string         `xml:"comment"`
		Hosts    string         `xml:"hosts"`
		PortList namedReference `xml:"port_list"`
	} `xml:"target"`
}

func taskStatus(value taskWire) TaskStatus {
	result := TaskStatus{
		ID:         value.ID,
		Name:       value.Name,
		Comment:    value.Comment,
		Status:     value.Status,
		Progress:   value.Progress,
		TargetID:   value.Target.ID,
		ConfigID:   value.Config.ID,
		ScannerID:  value.Scanner.ID,
		ScheduleID: value.Schedule.ID,
	}
	if value.LastReport.Report.ID != "" {
		report := value.LastReport.Report
		result.LastReport = &ReportStatus{
			ID:        report.ID,
			Status:    report.Status,
			Severity:  report.Severity,
			High:      report.ResultCount.High,
			Medium:    report.ResultCount.Medium,
			Low:       report.ResultCount.Low,
			Log:       report.ResultCount.Log,
			FalsePos:  report.ResultCount.FalsePos,
			ScanStart: parseGMPTime(report.ScanStart),
			ScanEnd:   parseGMPTime(report.ScanEnd),
		}
	}
	return result
}

func splitHosts(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	return parts
}

func parseGMPTime(value string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05"} {
		parsed, err := time.Parse(layout, strings.TrimSpace(value))
		if err == nil {
			return parsed
		}
	}
	return time.Time{}
}
