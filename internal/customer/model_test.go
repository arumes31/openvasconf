package customer

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeTags(t *testing.T) {
	t.Parallel()

	tags, err := NormalizeTags(" Production,WEB ", "web database")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(tags, ","); got != "database,production,web" {
		t.Errorf("NormalizeTags() = %q", got)
	}
	if _, err := NormalizeTags(strings.Repeat("x", 31)); err == nil {
		t.Error("long tag error = nil")
	}
	if _, err := NormalizeTags("1 2 3 4 5 6 7 8 9 10 11"); err == nil {
		t.Error("too many tags error = nil")
	}
}

func TestValidateSLAPolicy(t *testing.T) {
	t.Parallel()

	if err := ValidateSLAPolicy(SLAPolicy{CriticalDays: 1, HighDays: 2, MediumDays: 3, LowDays: 4}); err != nil {
		t.Fatalf("valid policy error = %v", err)
	}
	if err := ValidateSLAPolicy(SLAPolicy{HighDays: -1}); err == nil {
		t.Fatal("negative policy error = nil")
	}
}

func TestCustomerScheduleAndEffectiveSelections(t *testing.T) {
	t.Parallel()

	settings := Settings{
		Scanner:    Selection{ID: "scanner-default", Name: "Default scanner"},
		ScanConfig: Selection{ID: "config-default", Name: "Default config"},
		PortList:   Selection{ID: "ports-default", Name: "Default ports"},
	}
	value := Customer{ScheduleMinute: 9*60 + 5, Timezone: "UTC"}
	if got := value.ScheduleTime(); got != "09:05" {
		t.Errorf("ScheduleTime() = %q", got)
	}
	if got := value.EffectiveScanner(settings); got != settings.Scanner {
		t.Errorf("default scanner = %#v", got)
	}
	if got := value.EffectiveScanConfig(settings); got != settings.ScanConfig {
		t.Errorf("default config = %#v", got)
	}
	if got := value.EffectivePortList(settings); got != settings.PortList {
		t.Errorf("default ports = %#v", got)
	}

	value.ScannerID, value.ScannerName = "scanner-1", "Scanner 1"
	value.ScanConfigID, value.ScanConfigName = "config-1", "Config 1"
	value.PortListID, value.PortListName = "ports-1", "Ports 1"
	if got := value.EffectiveScanner(settings); got.ID != "scanner-1" || got.Name != "Scanner 1" {
		t.Errorf("scanner override = %#v", got)
	}
	if got := value.EffectiveScanConfig(settings); got.ID != "config-1" {
		t.Errorf("config override = %#v", got)
	}
	if got := value.EffectivePortList(settings); got.ID != "ports-1" {
		t.Errorf("ports override = %#v", got)
	}

	if _, err := (Customer{Timezone: "invalid/timezone"}).NextSchedule(time.Now()); err == nil {
		t.Error("invalid timezone error = nil")
	}
	if _, err := (Customer{Timezone: "UTC", ScheduleWeekday: 0}).NextSchedule(time.Now()); err == nil {
		t.Error("missing weekday error = nil")
	}
}
