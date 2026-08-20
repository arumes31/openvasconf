package gmp

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestClientOptions(t *testing.T) {
	t.Parallel()

	responses := []string{
		`<get_scanners_response status="200" status_text="OK">` +
			`<scanner id="scanner-1"><name>OpenVAS Default</name></scanner></get_scanners_response>`,
		`<get_configs_response status="200" status_text="OK">` +
			`<config id="config-1"><name>Full and fast</name></config></get_configs_response>`,
		`<get_port_lists_response status="200" status_text="OK">` +
			`<port_list id="ports-1"><name>All IANA assigned TCP</name></port_list>` +
			`</get_port_lists_response>`,
	}
	client := fakeClient(t, responses, nil)

	options, err := client.Options(t.Context())
	if err != nil {
		t.Fatalf("Options() error = %v", err)
	}
	if len(options.Scanners) != 1 || options.Scanners[0].ID != "scanner-1" {
		t.Errorf("scanners = %#v", options.Scanners)
	}
	if len(options.ScanConfigs) != 1 || options.ScanConfigs[0].Name != "Full and fast" {
		t.Errorf("scan configs = %#v", options.ScanConfigs)
	}
	if len(options.PortLists) != 1 || options.PortLists[0].ID != "ports-1" {
		t.Errorf("port lists = %#v", options.PortLists)
	}
}

func TestClientCreateTargetEscapesAndJoinsHosts(t *testing.T) {
	t.Parallel()

	requests := make(chan observedRequest, 2)
	client := fakeClient(
		t,
		[]string{`<create_target_response status="201" status_text="OK, resource created" id="target-1"/>`},
		requests,
	)
	id, err := client.CreateTarget(t.Context(), Target{
		Name:       `A & B`,
		Comment:    `owned <safely>`,
		Hosts:      []string{"10.0.0.0/24", "10.0.1.0/24"},
		PortListID: "port-list",
	})
	if err != nil {
		t.Fatalf("CreateTarget() error = %v", err)
	}
	if id != "target-1" {
		t.Errorf("id = %q, want target-1", id)
	}
	request := <-requests
	if request.Name != "create_target" {
		t.Fatalf("request name = %q", request.Name)
	}
	for _, expected := range []string{
		"<name>A &amp; B</name>",
		"<comment>owned &lt;safely&gt;</comment>",
		"<hosts>10.0.0.0/24,10.0.1.0/24</hosts>",
		`<port_list id="port-list"></port_list>`,
	} {
		if !strings.Contains(request.XML, expected) {
			t.Errorf("request XML %q does not contain %q", request.XML, expected)
		}
	}
}

func TestClientModifyTargetIncludesExcludeHosts(t *testing.T) {
	t.Parallel()

	requests := make(chan observedRequest, 1)
	client := fakeClient(
		t,
		[]string{`<modify_target_response status="200" status_text="OK"/>`},
		requests,
	)
	if err := client.ModifyTarget(t.Context(), "target-1", Target{
		Name:       "changed",
		Comment:    "owned",
		Hosts:      []string{"10.0.0.1"},
		PortListID: "port-list",
	}); err != nil {
		t.Fatalf("ModifyTarget() error = %v", err)
	}
	request := <-requests
	if request.Name != "modify_target" ||
		!strings.Contains(request.XML, `<exclude_hosts></exclude_hosts>`) {
		t.Errorf("modify target request = %#v", request)
	}
}

func TestClientDeleteUsesTrash(t *testing.T) {
	t.Parallel()

	requests := make(chan observedRequest, 2)
	client := fakeClient(
		t,
		[]string{`<delete_task_response status="200" status_text="OK"/>`},
		requests,
	)
	if err := client.DeleteTask(t.Context(), "task-1"); err != nil {
		t.Fatalf("DeleteTask() error = %v", err)
	}
	request := <-requests
	if !strings.Contains(request.XML, `task_id="task-1"`) ||
		!strings.Contains(request.XML, `ultimate="0"`) {
		t.Errorf("delete request = %q", request.XML)
	}
}

func TestClientProtocolError(t *testing.T) {
	t.Parallel()

	client := fakeClient(
		t,
		[]string{`<get_version_response status="400" status_text="Invalid request"/>`},
		nil,
	)
	_, err := client.Ping(t.Context())
	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Status != "400" {
		t.Fatalf("Ping() error = %v", err)
	}
}

func TestClientFindResourceByOwnershipMarker(t *testing.T) {
	t.Parallel()

	requests := make(chan observedRequest, 2)
	client := fakeClient(
		t,
		[]string{`<get_tasks_response status="200" status_text="OK">` +
			`<task id="foreign"><name>foreign</name><comment>someone else</comment></task>` +
			`<task id="owned"><name>managed</name>` +
			`<comment>openvasconf:v1;customer=customer-id</comment></task>` +
			`</get_tasks_response>`},
		requests,
	)
	resourceID, found, err := client.FindResource(
		t.Context(),
		"task",
		"openvasconf:v1;customer=customer-id",
	)
	if err != nil {
		t.Fatalf("FindResource() error = %v", err)
	}
	if !found || resourceID != "owned" {
		t.Errorf("FindResource() = %q, %t; want owned, true", resourceID, found)
	}
	request := <-requests
	if request.Name != "get_tasks" ||
		!strings.Contains(request.XML, `filter="first=1 rows=500"`) {
		t.Errorf("find request = %#v", request)
	}
}

func TestClientPaginatesResourceLists(t *testing.T) {
	t.Parallel()

	var firstPage strings.Builder
	firstPage.WriteString(`<get_tasks_response status="200" status_text="OK">`)
	for index := range listPageSize {
		_, _ = fmt.Fprintf(
			&firstPage,
			`<task id="task-%d"><comment>foreign</comment></task>`,
			index,
		)
	}
	firstPage.WriteString(`</get_tasks_response>`)
	responses := []string{
		firstPage.String(),
		`<get_tasks_response status="200" status_text="OK">` +
			`<task id="owned"><comment>openvasconf:owned</comment></task>` +
			`</get_tasks_response>`,
	}
	requests := make(chan observedRequest, 2)
	client := fakeClient(t, responses, requests)

	resourceID, found, err := client.FindResource(t.Context(), "task", "openvasconf:owned")
	if err != nil {
		t.Fatalf("FindResource() error = %v", err)
	}
	if !found || resourceID != "owned" {
		t.Fatalf("FindResource() = %q, %t; want owned, true", resourceID, found)
	}
	firstRequest := <-requests
	secondRequest := <-requests
	if !strings.Contains(firstRequest.XML, `filter="first=1 rows=500"`) {
		t.Errorf("first request = %q", firstRequest.XML)
	}
	if !strings.Contains(secondRequest.XML, `filter="first=501 rows=500"`) {
		t.Errorf("second request = %q", secondRequest.XML)
	}
}

type observedRequest struct {
	Name string
	XML  string
}

func fakeClient(t *testing.T, responses []string, requests chan<- observedRequest) *Client {
	t.Helper()
	responseIndex := 0
	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		response := responses[responseIndex]
		responseIndex++
		go serveFakeGMP(t, serverSide, response, requests)
		return clientSide, nil
	}
	return NewWithDialer("admin", "secret", time.Second, dial)
}

func serveFakeGMP(
	t *testing.T,
	connection net.Conn,
	response string,
	requests chan<- observedRequest,
) {
	t.Helper()
	defer connection.Close()
	decoder := xml.NewDecoder(connection)
	for index := range 2 {
		var request struct {
			XMLName    xml.Name
			Attributes []xml.Attr `xml:",any,attr"`
			InnerXML   string     `xml:",innerxml"`
		}
		if err := decoder.Decode(&request); err != nil {
			t.Errorf("fake server decode error = %v", err)
			return
		}
		if index == 0 {
			_, _ = connection.Write([]byte(
				`<authenticate_response status="200" status_text="OK"/>`,
			))
			continue
		}
		encoded, err := xml.Marshal(request)
		if err != nil {
			t.Errorf("fake server marshal error = %v", err)
			return
		}
		if requests != nil {
			requests <- observedRequest{Name: request.XMLName.Local, XML: string(encoded)}
		}
		_, _ = connection.Write([]byte(response))
	}
}
