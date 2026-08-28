package customer

import (
	"strings"
	"testing"
	"time"
)

func validExportCustomer() ExportCustomer {
	return ExportCustomer{
		ID: "customer-1", CID: "cid_1", Name: "Example", Description: "description",
		Tags: []string{"production"}, Networks: []string{"10.20.30.0/24"},
		ScheduleWeekday: Monday, ScheduleMinute: 8 * 60, Timezone: "UTC",
	}
}

func validExportDocument() ExportDocument {
	return ExportDocument{
		Version: ExportVersion, Timezone: "UTC",
		SchedulePolicy: SchedulePolicy{Weekdays: []int{Monday}, StartMinute: 0, EndMinute: 1439},
		Customers:      []ExportCustomer{validExportCustomer()},
	}
}

func TestNewExportDocument(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 28, 10, 0, 0, 0, time.FixedZone("test", 2*60*60))
	settings := Settings{
		Timezone:       "Europe/Vienna",
		SchedulePolicy: SchedulePolicy{Weekdays: []int{Monday}, StartMinute: 60, EndMinute: 120},
		Scanner:        Selection{ID: "scanner"}, ScanConfig: Selection{ID: "config"}, PortList: Selection{ID: "ports"},
	}
	customers := []Customer{{
		ID: "id-1", CID: "cid-1", Name: "Example", Description: "desc", Tags: []string{"tag"},
		ScheduleWeekday: 2, ScheduleMinute: 600, Timezone: "UTC",
		ScannerID: "scanner-override", ScanConfigID: "config-override", PortListID: "ports-override",
		Networks: []Network{{Prefix: "10.0.0.0/24"}},
	}}
	document := NewExportDocument(settings, customers, now)
	if document.Version != ExportVersion || !document.ExportedAt.Equal(now.UTC()) || len(document.Customers) != 1 {
		t.Fatalf("document = %#v", document)
	}
	if document.Customers[0].Networks[0] != "10.0.0.0/24" || document.Customers[0].Scanner.ID != "scanner-override" {
		t.Errorf("exported customer = %#v", document.Customers[0])
	}
}

func TestExportDocumentValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ExportDocument)
	}{
		{name: "unsupported version", mutate: func(value *ExportDocument) { value.Version = 2 }},
		{name: "too many customers", mutate: func(value *ExportDocument) { value.Customers = make([]ExportCustomer, 501) }},
		{name: "invalid timezone", mutate: func(value *ExportDocument) { value.Timezone = "invalid/timezone" }},
		{name: "invalid policy", mutate: func(value *ExportDocument) { value.SchedulePolicy.Weekdays = nil }},
		{name: "invalid customer", mutate: func(value *ExportDocument) { value.Customers[0].Name = "" }},
		{name: "duplicate name", mutate: func(value *ExportDocument) {
			duplicate := value.Customers[0]
			duplicate.ID = "customer-2"
			duplicate.Name = "EXAMPLE"
			value.Customers = append(value.Customers, duplicate)
		}},
		{name: "duplicate id", mutate: func(value *ExportDocument) {
			duplicate := value.Customers[0]
			duplicate.Name = "Other"
			value.Customers = append(value.Customers, duplicate)
		}},
	}
	if err := validExportDocument().Validate(); err != nil {
		t.Fatalf("valid document error = %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validExportDocument()
			test.mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestExportCustomerValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ExportCustomer)
	}{
		{name: "empty name", mutate: func(value *ExportCustomer) { value.Name = "" }},
		{name: "long name", mutate: func(value *ExportCustomer) { value.Name = strings.Repeat("x", 101) }},
		{name: "long description", mutate: func(value *ExportCustomer) { value.Description = strings.Repeat("x", 501) }},
		{name: "invalid cid", mutate: func(value *ExportCustomer) { value.CID = "spaces rejected" }},
		{name: "invalid tags", mutate: func(value *ExportCustomer) { value.Tags = []string{strings.Repeat("x", 31)} }},
		{name: "no networks", mutate: func(value *ExportCustomer) { value.Networks = nil }},
		{name: "too many networks", mutate: func(value *ExportCustomer) { value.Networks = make([]string, 2001) }},
		{name: "invalid network", mutate: func(value *ExportCustomer) { value.Networks = []string{"not-a-network"} }},
		{name: "invalid weekday", mutate: func(value *ExportCustomer) { value.ScheduleWeekday = 0 }},
		{name: "invalid minute", mutate: func(value *ExportCustomer) { value.ScheduleMinute = 1440 }},
		{name: "invalid timezone", mutate: func(value *ExportCustomer) { value.Timezone = "invalid/timezone" }},
	}
	if err := validExportCustomer().Validate(); err != nil {
		t.Fatalf("valid customer error = %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validExportCustomer()
			test.mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestValidateCID(t *testing.T) {
	t.Parallel()

	if err := ValidateCID("Acme_42.eu:prod-west"); err != nil {
		t.Fatalf("valid CID error = %v", err)
	}
	if err := ValidateCID(strings.Repeat("x", 101)); err == nil {
		t.Error("long CID error = nil")
	}
	if err := ValidateCID("bad/cid"); err == nil {
		t.Error("invalid character error = nil")
	}
}
