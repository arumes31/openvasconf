package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"openvasconf/internal/customer"
)

var importPreviewTokenPattern = regexp.MustCompile(`name="preview_token" value="([^"]+)"`)

func TestConfigurationExportImportLifecycle(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)
	seed := customer.Customer{
		ID: "portable-existing", Name: "portable", SafeName: "portable", CID: "cid_portable",
		Description: "before import", Tags: []string{"production"},
		ScheduleWeekday: 2, ScheduleMinute: 9 * 60, Timezone: "Europe/Vienna",
		Networks: []customer.Network{{
			ID: "portable-network", CustomerID: "portable-existing", Input: "10.50.0.0/24",
			Prefix: "10.50.0.0/24", Class: "PrivateIP",
		}},
	}
	if err := app.repository.CreateCustomer(t.Context(), seed); err != nil {
		t.Fatal(err)
	}

	response, err := app.client.Get(app.server.URL + "/export")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Content-Disposition"), "openvasconf-export.json") {
		t.Fatalf("export response = %d, %q", response.StatusCode, response.Header.Get("Content-Disposition"))
	}
	var document customer.ExportDocument
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if len(document.Customers) != 1 || document.Customers[0].CID != seed.CID {
		t.Fatalf("exported document = %#v", document)
	}
	document.Customers[0].Description = "updated through import"
	document.Customers = append(document.Customers, customer.ExportCustomer{
		Name: "portable-new", CID: "cid_new", Tags: []string{"new"}, Networks: []string{"7.7.7.9"},
		ScheduleWeekday: 3, ScheduleMinute: 10 * 60, Timezone: "UTC",
	})
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	response = postImportFile(t, app, payload)
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "Apply validated import") {
		t.Fatalf("import preview status = %d: %s", response.StatusCode, body)
	}
	match := importPreviewTokenPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("preview token missing: %s", body)
	}
	response = postForm(t, app, "/import/apply", mapValues(map[string]string{"preview_token": match[1]}))
	_ = readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("import apply final status = %d", response.StatusCode)
	}
	values, err := app.repository.Customers(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || app.syncer.count.Load() != 1 {
		t.Fatalf("customers = %d, sync triggers = %d", len(values), app.syncer.count.Load())
	}
	foundUpdated := false
	for _, value := range values {
		if value.ID == seed.ID {
			foundUpdated = value.Description == "updated through import" && value.DesiredRevision == 2
		}
	}
	if !foundUpdated {
		t.Error("existing customer was not updated by import")
	}
}

func TestImportPreviewRejectsMissingAndInvalidFiles(t *testing.T) {
	app := newTestWebApp(t)
	login(t, app)

	response := postForm(t, app, "/import/preview", nil)
	if body := readBody(t, response); !strings.Contains(body, "choose an openvasconf JSON export") {
		t.Fatalf("missing-file response = %s", body)
	}
	response = postImportFile(t, app, []byte(`{"unknown":true}`))
	if body := readBody(t, response); !strings.Contains(body, "invalid import file") {
		t.Fatalf("invalid-file response = %s", body)
	}
	response = postForm(t, app, "/import/apply", mapValues(map[string]string{"preview_token": "invalid"}))
	if body := readBody(t, response); !strings.Contains(body, "import confirmation is invalid") {
		t.Fatalf("invalid-token response = %s", body)
	}
}

func TestImportTokenValidation(t *testing.T) {
	t.Parallel()

	server := &Server{}
	document := customer.ExportDocument{
		Version: customer.ExportVersion, Timezone: "UTC",
		SchedulePolicy: customer.SchedulePolicy{Weekdays: []int{1}, StartMinute: 0, EndMinute: 1439},
	}
	valid, err := server.signImport(importEnvelope{Document: document, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	var destination importEnvelope
	if err := server.verifyImport(valid, &destination); err != nil {
		t.Fatalf("verifyImport(valid) error = %v", err)
	}
	for _, test := range []struct {
		name  string
		token func() string
	}{
		{name: "missing parts", token: func() string { return "invalid" }},
		{name: "bad payload encoding", token: func() string { return "!.AA" }},
		{name: "bad signature encoding", token: func() string { return "AA.!" }},
		{name: "wrong signature", token: func() string { return valid[:len(valid)-1] + "A" }},
		{name: "expired", token: func() string {
			token, signErr := server.signImport(importEnvelope{Document: document, ExpiresAt: time.Now().Add(-time.Minute)})
			if signErr != nil {
				t.Fatal(signErr)
			}
			return token
		}},
		{name: "invalid document", token: func() string {
			invalid := document
			invalid.Version = 999
			token, signErr := server.signImport(importEnvelope{Document: invalid, ExpiresAt: time.Now().Add(time.Minute)})
			if signErr != nil {
				t.Fatal(signErr)
			}
			return token
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := server.verifyImport(test.token(), &importEnvelope{}); err == nil {
				t.Fatal("verifyImport() error = nil")
			}
		})
	}
}

func TestImportedCustomerRejectsInvalidNetwork(t *testing.T) {
	t.Parallel()

	value := customer.ExportCustomer{
		Name: "invalid-network", Networks: []string{"not-a-network"},
		ScheduleWeekday: 1, ScheduleMinute: 60, Timezone: "UTC",
	}
	if _, err := importedCustomer(value); err == nil {
		t.Fatal("importedCustomer() error = nil")
	}
}

func postImportFile(t *testing.T, app testWebApp, payload []byte) *http.Response {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("configuration", "configuration.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("csrf_token", csrfCookie(t, app)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, app.server.URL+"/import/preview", &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := app.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
