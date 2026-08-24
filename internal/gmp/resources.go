package gmp

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

const (
	listPageSize = 500
	maxListPages = 100
)

type AliveTest string

const AliveTestConsiderAlive AliveTest = "Consider Alive"

type Option struct {
	ID   string
	Name string
}

type Options struct {
	Scanners    []Option
	ScanConfigs []Option
	PortLists   []Option
}

type Schedule struct {
	Name      string
	Comment   string
	ICalendar string
	Timezone  string
}

type Target struct {
	Name       string
	Comment    string
	Hosts      []string
	PortListID string
	AliveTest  AliveTest `json:"alive_test,omitempty"`
}

type Task struct {
	Name         string
	Comment      string
	ConfigID     string
	TargetID     string
	ScannerID    string
	ScheduleID   string
	ScheduleRuns int
}

func (c *Client) Ping(ctx context.Context) (string, error) {
	request := struct {
		XMLName xml.Name `xml:"get_version"`
	}{}
	var response struct {
		responseStatus
		Version string `xml:"version"`
	}
	if err := c.call(ctx, request, &response); err != nil {
		return "", err
	}
	if err := checkStatus("get_version", response.responseStatus); err != nil {
		return "", err
	}
	return response.Version, nil
}

func (c *Client) Options(ctx context.Context) (Options, error) {
	scanners, err := c.scanners(ctx)
	if err != nil {
		return Options{}, err
	}
	configs, err := c.scanConfigs(ctx)
	if err != nil {
		return Options{}, err
	}
	portLists, err := c.portLists(ctx)
	if err != nil {
		return Options{}, err
	}
	return Options{
		Scanners:    scanners,
		ScanConfigs: configs,
		PortLists:   portLists,
	}, nil
}

func (c *Client) scanners(ctx context.Context) ([]Option, error) {
	items, err := c.listResources(ctx, "get_scanners", "scanner")
	return options(items), err
}

func (c *Client) scanConfigs(ctx context.Context) ([]Option, error) {
	items, err := c.listResources(ctx, "get_configs", "config")
	return options(items), err
}

func (c *Client) portLists(ctx context.Context) ([]Option, error) {
	items, err := c.listResources(ctx, "get_port_lists", "port_list")
	return options(items), err
}

type listRequest struct {
	XMLName xml.Name
	Filter  string `xml:"filter,attr,omitempty"`
}

type namedResource struct {
	ID      string `xml:"id,attr"`
	Name    string `xml:"name"`
	Comment string `xml:"comment"`
}

func options(items []namedResource) []Option {
	result := make([]Option, 0, len(items))
	for _, item := range items {
		result = append(result, Option{ID: item.ID, Name: item.Name})
	}
	return result
}

func (c *Client) CreateSchedule(ctx context.Context, value Schedule) (string, error) {
	request := scheduleRequest{
		XMLName:  xml.Name{Local: "create_schedule"},
		Name:     value.Name,
		Comment:  value.Comment,
		Calendar: value.ICalendar,
		Timezone: value.Timezone,
	}
	return c.create(ctx, "create_schedule", request)
}

func (c *Client) ModifySchedule(ctx context.Context, scheduleID string, value Schedule) error {
	request := scheduleRequest{
		XMLName:    xml.Name{Local: "modify_schedule"},
		ResourceID: scheduleID,
		Name:       value.Name,
		Comment:    value.Comment,
		Calendar:   value.ICalendar,
		Timezone:   value.Timezone,
	}
	return c.modify(ctx, "modify_schedule", request)
}

type scheduleRequest struct {
	XMLName    xml.Name
	ResourceID string `xml:"schedule_id,attr,omitempty"`
	Name       string `xml:"name"`
	Comment    string `xml:"comment"`
	Calendar   string `xml:"icalendar"`
	Timezone   string `xml:"timezone"`
}

func (c *Client) CreateTarget(ctx context.Context, value Target) (string, error) {
	request := newTargetRequest(value)
	request.XMLName = xml.Name{Local: "create_target"}
	return c.create(ctx, "create_target", request)
}

func (c *Client) ModifyTarget(ctx context.Context, targetID string, value Target) error {
	emptyExcludeHosts := ""
	request := newTargetRequest(value)
	request.XMLName = xml.Name{Local: "modify_target"}
	request.ResourceID = targetID
	request.ExcludeHosts = &emptyExcludeHosts
	return c.modify(ctx, "modify_target", request)
}

func newTargetRequest(value Target) targetRequest {
	request := targetRequest{
		Name:    value.Name,
		Comment: value.Comment,
		Hosts:   strings.Join(value.Hosts, ","),
		PortList: resourceReference{
			ID: value.PortListID,
		},
	}
	if value.AliveTest != "" {
		request.AliveTests = value.AliveTest
	}
	return request
}

type targetRequest struct {
	XMLName      xml.Name
	ResourceID   string            `xml:"target_id,attr,omitempty"`
	Name         string            `xml:"name"`
	Comment      string            `xml:"comment"`
	Hosts        string            `xml:"hosts"`
	ExcludeHosts *string           `xml:"exclude_hosts,omitempty"`
	AliveTests   AliveTest         `xml:"alive_tests,omitempty"`
	PortList     resourceReference `xml:"port_list"`
}

func (c *Client) CreateTask(ctx context.Context, value Task) (string, error) {
	request := taskRequest{
		XMLName:   xml.Name{Local: "create_task"},
		Name:      value.Name,
		Comment:   value.Comment,
		Config:    resourceReference{ID: value.ConfigID},
		Target:    resourceReference{ID: value.TargetID},
		Scanner:   resourceReference{ID: value.ScannerID},
		Schedule:  resourceReference{ID: value.ScheduleID},
		Periods:   value.ScheduleRuns,
		Alterable: 1,
	}
	return c.create(ctx, "create_task", request)
}

func (c *Client) ModifyTask(ctx context.Context, taskID string, value Task) error {
	request := taskRequest{
		XMLName:    xml.Name{Local: "modify_task"},
		ResourceID: taskID,
		Name:       value.Name,
		Comment:    value.Comment,
		Config:     resourceReference{ID: value.ConfigID},
		Target:     resourceReference{ID: value.TargetID},
		Scanner:    resourceReference{ID: value.ScannerID},
		Schedule:   resourceReference{ID: value.ScheduleID},
		Periods:    value.ScheduleRuns,
		Alterable:  1,
	}
	return c.modify(ctx, "modify_task", request)
}

type taskRequest struct {
	XMLName    xml.Name
	ResourceID string            `xml:"task_id,attr,omitempty"`
	Name       string            `xml:"name"`
	Comment    string            `xml:"comment"`
	Config     resourceReference `xml:"config"`
	Target     resourceReference `xml:"target"`
	Scanner    resourceReference `xml:"scanner"`
	Schedule   resourceReference `xml:"schedule"`
	Periods    int               `xml:"schedule_periods"`
	Alterable  int               `xml:"alterable"`
}

type resourceReference struct {
	ID string `xml:"id,attr"`
}

func (c *Client) create(ctx context.Context, command string, request any) (string, error) {
	var response createResponse
	if err := c.call(ctx, request, &response); err != nil {
		return "", err
	}
	if err := checkStatus(command, response.responseStatus); err != nil {
		return "", err
	}
	if response.ID == "" {
		return "", fmt.Errorf("gmp: %s returned an empty id", command)
	}
	return response.ID, nil
}

func (c *Client) modify(ctx context.Context, command string, request any) error {
	var response responseStatus
	if err := c.call(ctx, request, &response); err != nil {
		return err
	}
	return checkStatus(command, response)
}

func (c *Client) DeleteSchedule(ctx context.Context, scheduleID string) error {
	return c.delete(ctx, "delete_schedule", "schedule_id", scheduleID)
}

func (c *Client) DeleteTarget(ctx context.Context, targetID string) error {
	return c.delete(ctx, "delete_target", "target_id", targetID)
}

func (c *Client) DeleteTask(ctx context.Context, taskID string) error {
	return c.delete(ctx, "delete_task", "task_id", taskID)
}

func (c *Client) delete(ctx context.Context, command, idAttribute, resourceID string) error {
	request := deleteRequest{
		XMLName:     xml.Name{Local: command},
		IDAttribute: idAttribute,
		ResourceID:  resourceID,
	}
	var response responseStatus
	if err := c.call(ctx, request, &response); err != nil {
		return err
	}
	return checkStatus(command, response)
}

type deleteRequest struct {
	XMLName     xml.Name
	IDAttribute string `xml:"-"`
	ResourceID  string `xml:"-"`
}

func (r deleteRequest) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
	start.Name = r.XMLName
	start.Attr = append(start.Attr,
		xml.Attr{Name: xml.Name{Local: r.IDAttribute}, Value: r.ResourceID},
		xml.Attr{Name: xml.Name{Local: "ultimate"}, Value: "0"},
	)
	if err := encoder.EncodeToken(start); err != nil {
		return err
	}
	return encoder.EncodeToken(start.End())
}

func (c *Client) ResourceComment(ctx context.Context, kind, resourceID string) (string, error) {
	command, idAttribute, itemName, err := resourceQuery(kind)
	if err != nil {
		return "", err
	}

	request := getResourceRequest{
		XMLName:     xml.Name{Local: command},
		IDAttribute: idAttribute,
		ResourceID:  resourceID,
	}
	var response resourceListResponse
	response.ItemName = itemName
	if err := c.call(ctx, request, &response); err != nil {
		return "", err
	}
	if err := checkStatus(command, response.responseStatus); err != nil {
		return "", err
	}
	if len(response.Items) == 0 {
		return "", ErrNotFound
	}
	return response.Items[0].Comment, nil
}

func (c *Client) FindResource(
	ctx context.Context,
	kind,
	ownershipMarker string,
) (string, bool, error) {
	command, _, itemName, err := resourceQuery(kind)
	if err != nil {
		return "", false, err
	}
	items, err := c.listResources(ctx, command, itemName)
	if err != nil {
		return "", false, err
	}

	resourceID := ""
	for _, item := range items {
		if !strings.Contains(item.Comment, ownershipMarker) {
			continue
		}
		if resourceID != "" {
			return "", false, fmt.Errorf(
				"gmp: multiple %s resources have ownership marker %q",
				kind,
				ownershipMarker,
			)
		}
		resourceID = item.ID
	}
	return resourceID, resourceID != "", nil
}

func (c *Client) listResources(
	ctx context.Context,
	command,
	itemName string,
) ([]namedResource, error) {
	items := make([]namedResource, 0)
	for page := range maxListPages {
		first := page*listPageSize + 1
		request := listRequest{
			XMLName: xml.Name{Local: command},
			Filter:  "first=" + strconv.Itoa(first) + " rows=" + strconv.Itoa(listPageSize),
		}
		var response resourceListResponse
		response.ItemName = itemName
		if err := c.call(ctx, request, &response); err != nil {
			return nil, err
		}
		if err := checkStatus(command, response.responseStatus); err != nil {
			return nil, err
		}
		items = append(items, response.Items...)
		if len(response.Items) < listPageSize {
			return items, nil
		}
	}
	return nil, fmt.Errorf(
		"gmp: %s exceeded pagination safety limit of %d resources",
		command,
		listPageSize*maxListPages,
	)
}

func resourceQuery(kind string) (command, idAttribute, itemName string, err error) {
	switch kind {
	case "schedule":
		return "get_schedules", "schedule_id", "schedule", nil
	case "target":
		return "get_targets", "target_id", "target", nil
	case "task":
		return "get_tasks", "task_id", "task", nil
	default:
		return "", "", "", fmt.Errorf("gmp: unsupported resource kind %q", kind)
	}
}

type getResourceRequest struct {
	XMLName     xml.Name
	IDAttribute string `xml:"-"`
	ResourceID  string `xml:"-"`
}

func (r getResourceRequest) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
	start.Name = r.XMLName
	start.Attr = append(start.Attr,
		xml.Attr{Name: xml.Name{Local: r.IDAttribute}, Value: r.ResourceID},
	)
	if err := encoder.EncodeToken(start); err != nil {
		return err
	}
	return encoder.EncodeToken(start.End())
}

type resourceListResponse struct {
	responseStatus
	ItemName string          `xml:"-"`
	Items    []namedResource `xml:"-"`
}

func (r *resourceListResponse) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	for _, attribute := range start.Attr {
		switch attribute.Name.Local {
		case "status":
			r.Status = attribute.Value
		case "status_text":
			r.StatusText = attribute.Value
		}
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Local == r.ItemName {
				var item namedResource
				if err := decoder.DecodeElement(&item, &value); err != nil {
					return err
				}
				r.Items = append(r.Items, item)
			}
		case xml.EndElement:
			if value.Name == start.Name {
				return nil
			}
		}
	}
}
