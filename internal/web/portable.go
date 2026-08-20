package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/id"
	"openvasconf/internal/networkplan"
)

type importEnvelope struct {
	Document  customer.ExportDocument `json:"document"`
	ExpiresAt time.Time               `json:"expires_at"`
}

func (s *Server) exportConfiguration(response http.ResponseWriter, request *http.Request) {
	settings, err := s.repository.Settings(request.Context())
	if err != nil {
		s.internalError(response, err)
		return
	}
	values, err := s.repository.Customers(request.Context(), false)
	if err != nil {
		s.internalError(response, err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Disposition", `attachment; filename="openvasconf-export.json"`)
	encoder := json.NewEncoder(response)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(customer.NewExportDocument(settings, values, time.Now())); err != nil {
		s.logger.Error("export encoding failed", "error", err)
	}
}

func (s *Server) importPage(response http.ResponseWriter, request *http.Request) {
	s.render(response, request, "import.html", pageData{Title: "Import configuration", Authenticated: true})
}

func (s *Server) importPreview(response http.ResponseWriter, request *http.Request) {
	file, _, err := request.FormFile("configuration")
	if err != nil {
		s.renderImportError(response, request, errors.New("choose an openvasconf JSON export"))
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var document customer.ExportDocument
	if err := decoder.Decode(&document); err != nil {
		s.renderImportError(response, request, fmt.Errorf("invalid import file: %w", err))
		return
	}
	if err := document.Validate(); err != nil {
		s.renderImportError(response, request, err)
		return
	}
	existing, err := s.repository.Customers(request.Context(), false)
	if err != nil {
		s.internalError(response, err)
		return
	}
	byID := make(map[string]struct{}, len(existing))
	byName := make(map[string]string, len(existing))
	for _, value := range existing {
		byID[value.ID] = struct{}{}
		byName[strings.ToLower(value.Name)] = value.ID
	}
	preview := &importPreview{Customers: len(document.Customers)}
	for index, value := range document.Customers {
		preview.Networks += len(value.Networks)
		_, updates := byID[value.ID]
		if !updates && value.ID == "" {
			if existingID, found := byName[strings.ToLower(value.Name)]; found {
				document.Customers[index].ID = existingID
				updates = true
			}
		} else if existingID, found := byName[strings.ToLower(value.Name)]; found && existingID != value.ID {
			s.renderImportError(response, request, fmt.Errorf("customer name %q conflicts with an existing customer", value.Name))
			return
		}
		if updates {
			preview.Updates++
		} else {
			preview.Creates++
		}
	}
	token, err := s.signImport(importEnvelope{Document: document, ExpiresAt: time.Now().Add(15 * time.Minute)})
	if err != nil {
		s.internalError(response, err)
		return
	}
	s.render(response, request, "import.html", pageData{
		Title: "Review import", Authenticated: true, Import: preview, PreviewToken: token,
	})
}

func (s *Server) importApply(response http.ResponseWriter, request *http.Request) {
	var envelope importEnvelope
	if err := s.verifyImport(request.PostForm.Get("preview_token"), &envelope); err != nil {
		s.renderImportError(response, request, err)
		return
	}
	settings, err := s.repository.Settings(request.Context())
	if err != nil {
		s.internalError(response, err)
		return
	}
	settings.Timezone = envelope.Document.Timezone
	settings.SchedulePolicy = envelope.Document.SchedulePolicy
	settings.Scanner = envelope.Document.Scanner
	settings.ScanConfig = envelope.Document.ScanConfig
	settings.PortList = envelope.Document.PortList
	values := make([]customer.Customer, 0, len(envelope.Document.Customers))
	for _, portable := range envelope.Document.Customers {
		value, convertErr := importedCustomer(portable)
		if convertErr != nil {
			s.renderImportError(response, request, convertErr)
			return
		}
		values = append(values, value)
	}
	if err := s.repository.ApplyImport(request.Context(), settings, values); err != nil {
		s.renderImportError(response, request, err)
		return
	}
	s.syncer.Trigger()
	http.Redirect(response, request, "/?notice=import-applied", http.StatusSeeOther)
}

func importedCustomer(value customer.ExportCustomer) (customer.Customer, error) {
	customerID := value.ID
	var err error
	if customerID == "" {
		customerID, err = id.New()
		if err != nil {
			return customer.Customer{}, err
		}
	}
	tags, err := customer.NormalizeTags(value.Tags...)
	if err != nil {
		return customer.Customer{}, err
	}
	result := customer.Customer{
		ID: customerID, Name: strings.TrimSpace(value.Name), SafeName: networkplan.SafeName(value.Name),
		Description: value.Description, Tags: tags, ScheduleWeekday: value.ScheduleWeekday,
		ScheduleMinute: value.ScheduleMinute, Timezone: value.Timezone,
		ScannerID: value.Scanner.ID, ScannerName: value.Scanner.Name,
		ScanConfigID: value.ScanConfig.ID, ScanConfigName: value.ScanConfig.Name,
		PortListID: value.PortList.ID, PortListName: value.PortList.Name,
		Networks: make([]customer.Network, 0, len(value.Networks)),
	}
	for _, input := range value.Networks {
		prefix, parseErr := networkplan.Parse(input)
		if parseErr != nil {
			return customer.Customer{}, parseErr
		}
		plan, buildErr := networkplan.Build(networkplan.Input{CustomerName: value.Name, Networks: []string{prefix.String()}})
		if buildErr != nil {
			return customer.Customer{}, buildErr
		}
		networkID, newErr := id.New()
		if newErr != nil {
			return customer.Customer{}, newErr
		}
		result.Networks = append(result.Networks, customer.Network{ID: networkID, CustomerID: customerID, Input: input, Prefix: prefix.String(), Class: string(plan.Targets[0].Class)})
	}
	return result, nil
}

func (s *Server) signImport(value importEnvelope) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.previewKey[:])
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Server) verifyImport(token string, destination *importEnvelope) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("import confirmation is invalid; preview the file again")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("import confirmation is invalid; preview the file again")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("import confirmation is invalid; preview the file again")
	}
	mac := hmac.New(sha256.New, s.previewKey[:])
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return errors.New("import confirmation is invalid; preview the file again")
	}
	if err := json.Unmarshal(payload, destination); err != nil || time.Now().After(destination.ExpiresAt) {
		return errors.New("import confirmation expired; preview the file again")
	}
	return destination.Document.Validate()
}

func (s *Server) renderImportError(response http.ResponseWriter, request *http.Request, err error) {
	s.render(response, request, "import.html", pageData{Title: "Import configuration", Authenticated: true, Error: err.Error()})
}
