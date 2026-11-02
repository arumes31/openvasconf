package web

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestCustomerPreviewRejectsDuplicateNetworks(t *testing.T) {
	for _, test := range []struct {
		name, inputs, prefix string
	}{
		{"same address", "10.55.0.42\n10.55.0.42", "10.55.0.42/32"},
		{"comments and explicit mask", "10.55.0.42 #primary site\n10.55.0.42/32 #other site", "10.55.0.42/32"},
		{"same masked network", "10.20.1.123/24\n10.20.1.0/24", "10.20.1.0/24"},
		{"range repeats prefix", "10.20.1.0-10.20.1.255\n10.20.1.0/24", "10.20.1.0/24"},
	} {
		for _, editing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/edit=%t", test.name, editing), func(t *testing.T) {
				app := newTestWebApp(t)
				login(t, app)
				path := "/customers/preview"
				if editing {
					value := seedActionCustomer(t, app)
					path = "/customers/" + value.ID + "/preview"
				}
				response := postForm(t, app, path, url.Values{
					"name": {"duplicate-check"}, "networks": {test.inputs},
					"schedule_weekday": {"4"}, "schedule_time": {"14:04"},
				})
				body := readBody(t, response)
				for _, expected := range []string{"duplicate network/IP", "entry 2", "entry 1", test.prefix, `role="alert"`} {
					if !strings.Contains(body, expected) {
						t.Errorf("duplicate error missing %q", expected)
					}
				}
				if strings.Contains(body, `name="preview_token"`) || strings.Contains(body, "Confirm and synchronize") {
					t.Fatal("duplicate input can still be confirmed")
				}
				if !strings.Contains(body, test.inputs) {
					t.Fatal("duplicate input was removed instead of being preserved for correction")
				}
				values, err := app.repository.Customers(t.Context(), false)
				want := 0
				if editing {
					want = 1
				}
				if err != nil || len(values) != want || (editing && len(values[0].Networks) != 1) {
					t.Fatalf("invalid preview changed saved customers: %#v, %v", values, err)
				}
				if app.syncer.count.Load() != 0 {
					t.Fatal("duplicate input triggered synchronization")
				}
			})
		}
	}
}

func TestCustomerNetworkErrorPreservesEditForm(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)
	value := seedActionCustomer(t, app)
	path := "/customers/" + value.ID + "/preview"
	response := postForm(t, app, path, url.Values{
		"name": {value.Name}, "networks": {"invalid-address"},
		"schedule_weekday": {"4"}, "schedule_time": {"14:04"},
	})
	body := readBody(t, response)
	for _, expected := range []string{`action="` + path + `"`, `value="4" selected`, `name="schedule_time" type="time" value="14:04"`, "invalid-address"} {
		if !strings.Contains(body, expected) {
			t.Errorf("error response lost form state %q", expected)
		}
	}
	if strings.Contains(body, `name="preview_token"`) {
		t.Fatal("invalid input can be confirmed")
	}
}

func TestCustomerTenUniqueNetworksSurviveSaveAndReload(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)
	entries := make([]string, 10)
	for i := range entries {
		entries[i] = fmt.Sprintf("10.22.0.%d # branch %d", i+1, i+1)
	}
	response := postForm(t, app, "/customers/preview", url.Values{"name": {"ten-networks"}, "networks": {strings.Join(entries, "\n")}})
	body := readBody(t, response)
	match := regexp.MustCompile(`name="preview_token" value="([^"]+)"`).FindStringSubmatch(body)
	if response.StatusCode != http.StatusOK || len(match) != 2 {
		t.Fatalf("unique entries rejected: %s", body)
	}
	response = postForm(t, app, "/customers", url.Values{"preview_token": {match[1]}})
	_ = readBody(t, response)
	values, err := app.repository.Customers(t.Context(), false)
	if err != nil || len(values) != 1 || len(values[0].Networks) != 10 {
		t.Fatalf("saved values = %#v, %v", values, err)
	}
	response, err = app.client.Get(app.server.URL + "/customers/" + values[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readBody(t, response), entries[9]) {
		t.Fatal("tenth unique entry missing after reload")
	}
}
