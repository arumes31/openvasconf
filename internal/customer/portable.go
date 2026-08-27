package customer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"openvasconf/internal/networkplan"
)

const ExportVersion = 1

type ExportDocument struct {
	Version        int              `json:"version"`
	ExportedAt     time.Time        `json:"exported_at"`
	Timezone       string           `json:"timezone"`
	SchedulePolicy SchedulePolicy   `json:"schedule_policy"`
	Scanner        Selection        `json:"default_scanner"`
	ScanConfig     Selection        `json:"default_scan_config"`
	PortList       Selection        `json:"default_port_list"`
	Customers      []ExportCustomer `json:"customers"`
}

type ExportCustomer struct {
	ID              string    `json:"id,omitempty"`
	CID             string    `json:"cid,omitempty"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Tags            []string  `json:"tags,omitempty"`
	Networks        []string  `json:"networks"`
	ScheduleWeekday int       `json:"schedule_weekday"`
	ScheduleMinute  int       `json:"schedule_minute"`
	Timezone        string    `json:"timezone"`
	Scanner         Selection `json:"scanner_override,omitempty"`
	ScanConfig      Selection `json:"scan_config_override,omitempty"`
	PortList        Selection `json:"port_list_override,omitempty"`
}

func NewExportDocument(settings Settings, customers []Customer, now time.Time) ExportDocument {
	values := make([]ExportCustomer, 0, len(customers))
	for _, value := range customers {
		networks := make([]string, 0, len(value.Networks))
		for _, network := range value.Networks {
			networks = append(networks, network.Prefix)
		}
		values = append(values, ExportCustomer{
			ID:              value.ID,
			CID:             value.CID,
			Name:            value.Name,
			Description:     value.Description,
			Tags:            value.Tags,
			Networks:        networks,
			ScheduleWeekday: value.ScheduleWeekday,
			ScheduleMinute:  value.ScheduleMinute,
			Timezone:        value.Timezone,
			Scanner:         Selection{ID: value.ScannerID, Name: value.ScannerName},
			ScanConfig:      Selection{ID: value.ScanConfigID, Name: value.ScanConfigName},
			PortList:        Selection{ID: value.PortListID, Name: value.PortListName},
		})
	}
	return ExportDocument{
		Version:        ExportVersion,
		ExportedAt:     now.UTC(),
		Timezone:       settings.Timezone,
		SchedulePolicy: settings.SchedulePolicy,
		Scanner:        settings.Scanner,
		ScanConfig:     settings.ScanConfig,
		PortList:       settings.PortList,
		Customers:      values,
	}
}

func (d ExportDocument) Validate() error {
	if d.Version != ExportVersion {
		return fmt.Errorf("customer: unsupported export version %d", d.Version)
	}
	if len(d.Customers) > 500 {
		return errors.New("customer: import contains more than 500 customers")
	}
	if _, err := time.LoadLocation(d.Timezone); err != nil {
		return fmt.Errorf("customer: invalid export timezone %q: %w", d.Timezone, err)
	}
	if err := ValidateSchedulePolicy(d.SchedulePolicy); err != nil {
		return err
	}
	names := make(map[string]struct{}, len(d.Customers))
	ids := make(map[string]struct{}, len(d.Customers))
	for index, value := range d.Customers {
		if err := value.Validate(); err != nil {
			return fmt.Errorf("customer: import customer %d: %w", index+1, err)
		}
		nameKey := strings.ToLower(value.Name)
		if _, duplicate := names[nameKey]; duplicate {
			return fmt.Errorf("customer: duplicate imported customer name %q", value.Name)
		}
		names[nameKey] = struct{}{}
		if value.ID != "" {
			if _, duplicate := ids[value.ID]; duplicate {
				return fmt.Errorf("customer: duplicate imported customer id %q", value.ID)
			}
			ids[value.ID] = struct{}{}
		}
	}
	return nil
}

func (c ExportCustomer) Validate() error {
	if name := strings.TrimSpace(c.Name); name == "" || len(name) > 100 {
		return errors.New("customer name must contain 1 to 100 characters")
	}
	if len(c.Description) > 500 {
		return errors.New("customer description must contain at most 500 characters")
	}
	if err := ValidateCID(c.CID); err != nil {
		return err
	}
	if _, err := NormalizeTags(c.Tags...); err != nil {
		return err
	}
	if len(c.Networks) == 0 || len(c.Networks) > 2_000 {
		return errors.New("customer must contain 1 to 2000 networks")
	}
	if _, err := networkplan.Build(networkplan.Input{
		CustomerName: c.Name,
		Networks:     c.Networks,
	}); err != nil {
		return err
	}
	if c.ScheduleWeekday < Monday || c.ScheduleWeekday > Sunday {
		return errors.New("customer schedule weekday must be Monday through Sunday")
	}
	if c.ScheduleMinute < EarliestMinute || c.ScheduleMinute > LatestMinute {
		return errors.New("customer schedule time must be within one day between 00:00 and 23:59")
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return fmt.Errorf("invalid customer timezone %q: %w", c.Timezone, err)
	}
	return nil
}

// ValidateCID accepts the customer routing identifiers supported by
// Hookwise/ConnectWise without allowing whitespace or control characters.
func ValidateCID(value string) error {
	if len(value) > 100 {
		return errors.New("customer cid must contain at most 100 characters")
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') &&
			!(char >= '0' && char <= '9') && !strings.ContainsRune("._:-", char) {
			return errors.New("customer cid may contain only letters, numbers, dot, underscore, colon, and hyphen")
		}
	}
	return nil
}
