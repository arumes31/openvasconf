package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/gmp"
	"openvasconf/internal/id"
	"openvasconf/internal/networkplan"
	"openvasconf/internal/store"
)

func (s *Server) customerNew(response http.ResponseWriter, request *http.Request) {
	options, optionsError := s.greenbone.Options(request.Context())
	settings, settingsError := s.repository.Settings(request.Context())
	form := customerForm{}
	if settingsError == nil {
		weekday, minute, scheduleErr := customer.RandomScheduleWithPolicy(nil, settings.SchedulePolicy)
		if scheduleErr == nil {
			form.Weekday, form.Time = weekday, customer.MinuteTime(minute)
		}
	}
	data := pageData{
		Title:         "New customer",
		Authenticated: true,
		Options:       options,
		Form:          form,
		Settings:      settings,
	}
	if optionsError != nil {
		data.GreenboneError = optionsError.Error()
	} else if settingsError != nil {
		data.Error = settingsError.Error()
	}
	s.render(response, request, "customer.html", data)
}

func (s *Server) customerEdit(response http.ResponseWriter, request *http.Request) {
	value, err := s.repository.Customer(request.Context(), request.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || value.DeletedAt != nil {
		http.NotFound(response, request)
		return
	}
	if err != nil {
		s.internalError(response, err)
		return
	}
	options, optionsError := s.greenbone.Options(request.Context())
	settings, settingsError := s.repository.Settings(request.Context())
	analysis, analysisError := networkplan.Analyze(networkplan.Input{CustomerName: value.Name, Networks: networkInputsForWeb(value.Networks)})
	resources, resourcesError := s.repository.ManagedResources(request.Context(), value.ID)
	taskStates := make(map[string]gmp.TaskStatus)
	if operations, ok := s.greenbone.(operationalGreenbone); ok {
		if tasks, taskErr := operations.Tasks(request.Context()); taskErr == nil {
			for _, task := range tasks {
				taskStates[task.ID] = task
			}
		}
	}
	data := pageData{
		Title:         "Edit " + value.Name,
		Authenticated: true,
		Options:       options,
		Form:          formFromCustomer(value),
		Settings:      settings,
		Analysis:      analysis,
		Plan:          analysis.Plan,
		Resources:     resources,
		TaskStates:    taskStates,
		Notice:        noticeText(request.URL.Query().Get("notice")),
	}
	if optionsError != nil {
		data.GreenboneError = optionsError.Error()
	} else if settingsError != nil {
		data.Error = settingsError.Error()
	} else if analysisError != nil {
		data.Error = analysisError.Error()
	} else if resourcesError != nil {
		data.Error = resourcesError.Error()
	}
	s.render(response, request, "customer.html", data)
}

func (s *Server) customerPreviewNew(response http.ResponseWriter, request *http.Request) {
	s.customerPreview(response, request, nil)
}

func (s *Server) customerPreviewExisting(response http.ResponseWriter, request *http.Request) {
	value, err := s.repository.Customer(request.Context(), request.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || value.DeletedAt != nil {
		http.NotFound(response, request)
		return
	}
	if err != nil {
		s.internalError(response, err)
		return
	}
	s.customerPreview(response, request, &value)
}

func (s *Server) customerPreview(
	response http.ResponseWriter,
	request *http.Request,
	existing *customer.Customer,
) {
	value, plan, form, err := s.customerFromForm(request, existing)
	options, optionsError := s.greenbone.Options(request.Context())
	data := pageData{
		Title:         "Customer preview",
		Authenticated: true,
		Options:       options,
		Form:          form,
		Plan:          plan,
		Analysis:      networkplan.Analysis{Plan: plan},
	}
	if settings, settingsErr := s.repository.Settings(request.Context()); settingsErr == nil {
		data.Settings = settings
	}
	if err != nil {
		data.Error = err.Error()
	} else {
		analysis, analyzeErr := networkplan.Analyze(networkplan.Input{
			CustomerName: value.Name,
			Networks:     networkInputsForWeb(value.Networks),
		})
		if analyzeErr != nil {
			data.Error = analyzeErr.Error()
		} else {
			data.Analysis = analysis
			data.Preview = buildChangePreview(existing, value, analysis.Plan)
			envelope := previewEnvelope{Customer: value, ExpiresAt: time.Now().Add(15 * time.Minute)}
			if existing != nil {
				envelope.Revision = existing.DesiredRevision
			}
			data.PreviewToken, err = s.signPreview(envelope)
			if err != nil {
				data.Error = err.Error()
			}
			if existing == nil {
				data.ConfirmPath = "/customers"
			} else {
				data.ConfirmPath = "/customers/" + existing.ID
			}
		}
	}
	if optionsError != nil {
		data.GreenboneError = optionsError.Error()
	}
	s.render(response, request, "customer.html", data)
}

func (s *Server) customerCreate(response http.ResponseWriter, request *http.Request) {
	token := request.PostForm.Get("preview_token")
	if token == "" {
		http.Error(response, "preview confirmation is required; review the customer before saving", http.StatusBadRequest)
		return
	}
	var envelope previewEnvelope
	if err := s.verifyPreview(token, &envelope); err != nil {
		response.WriteHeader(http.StatusBadRequest)
		s.renderCustomerError(response, request, customerForm{}, err)
		return
	}
	value := envelope.Customer
	form := formFromCustomer(value)
	form.Editing = false
	if value.ID == "" {
		err := errors.New("preview confirmation is invalid; review the customer again")
		response.WriteHeader(http.StatusBadRequest)
		s.renderCustomerError(response, request, form, err)
		return
	}
	if err := s.repository.CreateCustomer(request.Context(), value); err != nil {
		s.renderCustomerError(response, request, form, err)
		return
	}
	s.syncer.Trigger()
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

func (s *Server) customerUpdate(response http.ResponseWriter, request *http.Request) {
	existing, err := s.repository.Customer(request.Context(), request.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || existing.DeletedAt != nil {
		http.NotFound(response, request)
		return
	}
	if err != nil {
		s.internalError(response, err)
		return
	}
	token := request.PostForm.Get("preview_token")
	if token == "" {
		http.Error(response, "preview confirmation is required; review the customer before saving", http.StatusBadRequest)
		return
	}
	var envelope previewEnvelope
	if err := s.verifyPreview(token, &envelope); err != nil {
		response.WriteHeader(http.StatusBadRequest)
		s.renderCustomerError(response, request, customerForm{}, err)
		return
	}
	form := formFromCustomer(envelope.Customer)
	if envelope.Customer.ID != existing.ID || envelope.Revision != existing.DesiredRevision {
		response.WriteHeader(http.StatusBadRequest)
		s.renderCustomerError(response, request, form, errors.New("customer changed after preview; review the current definition again"))
		return
	}
	value := envelope.Customer
	if value.ID == "" {
		err := errors.New("preview confirmation is invalid; review the customer again")
		response.WriteHeader(http.StatusBadRequest)
		s.renderCustomerError(response, request, form, err)
		return
	}
	if err := s.repository.UpdateCustomer(request.Context(), value); err != nil {
		s.renderCustomerError(response, request, form, err)
		return
	}
	s.syncer.Trigger()
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

func (s *Server) customerDelete(response http.ResponseWriter, request *http.Request) {
	if err := s.repository.SoftDeleteCustomer(
		request.Context(),
		request.PathValue("id"),
	); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(response, request)
			return
		}
		s.internalError(response, err)
		return
	}
	s.syncer.Trigger()
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

func (s *Server) renderCustomerError(
	response http.ResponseWriter,
	request *http.Request,
	form customerForm,
	formError error,
) {
	options, optionsError := s.greenbone.Options(request.Context())
	data := pageData{
		Title:         "Customer",
		Authenticated: true,
		Options:       options,
		Form:          form,
		Error:         formError.Error(),
	}
	if optionsError != nil {
		data.GreenboneError = optionsError.Error()
	}
	s.render(response, request, "customer.html", data)
}

func (s *Server) customerFromForm(
	request *http.Request,
	existing *customer.Customer,
) (customer.Customer, networkplan.Plan, customerForm, error) {
	form := customerForm{
		Name:         strings.TrimSpace(request.PostForm.Get("name")),
		Description:  strings.TrimSpace(request.PostForm.Get("description")),
		Tags:         strings.TrimSpace(request.PostForm.Get("tags")),
		Networks:     strings.TrimSpace(request.PostForm.Get("networks")),
		ScannerID:    request.PostForm.Get("scanner_id"),
		ScanConfigID: request.PostForm.Get("scan_config_id"),
		PortListID:   request.PostForm.Get("port_list_id"),
		Editing:      existing != nil,
	}
	if len(form.Description) > 500 {
		return customer.Customer{}, networkplan.Plan{}, form, errors.New("customer description must contain at most 500 characters")
	}
	tags, err := customer.NormalizeTags(form.Tags)
	if err != nil {
		return customer.Customer{}, networkplan.Plan{}, form, err
	}
	if existing != nil {
		form.ID = existing.ID
		form.Schedule = formFromCustomer(*existing).Schedule
	}
	if form.Name == "" || len(form.Name) > 100 {
		return customer.Customer{}, networkplan.Plan{}, form, errors.New("customer name must contain 1 to 100 characters")
	}
	inputs := splitNetworkInputs(form.Networks)
	if len(inputs) == 0 {
		return customer.Customer{}, networkplan.Plan{}, form, errors.New("enter at least one ipv4 address, cidr, or start-end range")
	}
	plan, err := networkplan.Build(networkplan.Input{
		CustomerName: form.Name,
		Networks:     inputs,
	})
	if err != nil {
		return customer.Customer{}, networkplan.Plan{}, form, err
	}

	settings, err := s.repository.Settings(request.Context())
	if err != nil {
		return customer.Customer{}, networkplan.Plan{}, form, err
	}
	value := customer.Customer{
		Name:        form.Name,
		SafeName:    plan.CustomerKey,
		Description: form.Description,
		Tags:        tags,
		Timezone:    settings.Timezone,
		Networks:    make([]customer.Network, 0, len(inputs)),
	}
	if existing == nil {
		value.ID, err = id.New()
		if err != nil {
			return customer.Customer{}, networkplan.Plan{}, form, err
		}
		value.ScheduleWeekday, value.ScheduleMinute, err = customer.RandomScheduleWithPolicy(nil, settings.SchedulePolicy)
		if err != nil {
			return customer.Customer{}, networkplan.Plan{}, form, err
		}
	} else {
		value.ID = existing.ID
		value.ScheduleWeekday = existing.ScheduleWeekday
		value.ScheduleMinute = existing.ScheduleMinute
		value.Timezone = existing.Timezone
		value.CreatedAt = existing.CreatedAt
	}
	if weekdayText, timeText := request.PostForm.Get("schedule_weekday"), request.PostForm.Get("schedule_time"); weekdayText != "" || timeText != "" {
		weekday, parseErr := strconv.Atoi(weekdayText)
		if parseErr != nil || weekday < customer.Monday || weekday > customer.Sunday {
			return customer.Customer{}, networkplan.Plan{}, form, errors.New("schedule weekday must be Monday through Sunday")
		}
		parsedTime, parseErr := time.Parse("15:04", timeText)
		if parseErr != nil {
			return customer.Customer{}, networkplan.Plan{}, form, errors.New("schedule time must use HH:MM")
		}
		minute := parsedTime.Hour()*60 + parsedTime.Minute()
		if minute < customer.EarliestMinute || minute > customer.LatestMinute {
			return customer.Customer{}, networkplan.Plan{}, form, errors.New("schedule time must be within one day between 00:00 and 23:59")
		}
		value.ScheduleWeekday, value.ScheduleMinute = weekday, minute
	}
	form.Weekday, form.Time = value.ScheduleWeekday, value.ScheduleTime()
	form.Schedule = formFromCustomer(value).Schedule

	options, err := s.greenbone.Options(request.Context())
	hasOverride := form.ScannerID != "" || form.ScanConfigID != "" || form.PortListID != ""
	if err != nil && hasOverride {
		return customer.Customer{}, networkplan.Plan{}, form, errors.New(
			"greenbone options are unavailable; remove overrides or try again",
		)
	}
	if form.ScannerID != "" {
		selection, selectErr := selectedOption(options.Scanners, form.ScannerID)
		if selectErr != nil {
			return customer.Customer{}, networkplan.Plan{}, form, selectErr
		}
		value.ScannerID, value.ScannerName = selection.ID, selection.Name
	}
	if form.ScanConfigID != "" {
		selection, selectErr := selectedOption(options.ScanConfigs, form.ScanConfigID)
		if selectErr != nil {
			return customer.Customer{}, networkplan.Plan{}, form, selectErr
		}
		value.ScanConfigID, value.ScanConfigName = selection.ID, selection.Name
	}
	if form.PortListID != "" {
		selection, selectErr := selectedOption(options.PortLists, form.PortListID)
		if selectErr != nil {
			return customer.Customer{}, networkplan.Plan{}, form, selectErr
		}
		value.PortListID, value.PortListName = selection.ID, selection.Name
	}

	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		prefixes, expandErr := networkplan.Expand(input)
		if expandErr != nil {
			return customer.Customer{}, networkplan.Plan{}, form, expandErr
		}
		for _, prefix := range prefixes {
			if _, duplicate := seen[prefix.String()]; duplicate {
				continue
			}
			seen[prefix.String()] = struct{}{}
			inputPlan, buildErr := networkplan.Build(networkplan.Input{
				CustomerName: form.Name,
				Networks:     []string{prefix.String()},
			})
			if buildErr != nil {
				return customer.Customer{}, networkplan.Plan{}, form, buildErr
			}
			networkID, idErr := id.New()
			if idErr != nil {
				return customer.Customer{}, networkplan.Plan{}, form, idErr
			}
			value.Networks = append(value.Networks, customer.Network{
				ID:         networkID,
				CustomerID: value.ID,
				Input:      input,
				Prefix:     prefix.String(),
				Class:      string(inputPlan.Targets[0].Class),
			})
		}
	}
	return value, plan, form, nil
}

type previewEnvelope struct {
	Customer  customer.Customer `json:"customer"`
	Revision  int64             `json:"revision"`
	ExpiresAt time.Time         `json:"expires_at"`
}

func (s *Server) signPreview(value previewEnvelope) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encoding preview: %w", err)
	}
	mac := hmac.New(sha256.New, s.previewKey[:])
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Server) verifyPreview(token string, destination *previewEnvelope) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("preview confirmation is invalid; review the customer again")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("preview confirmation is invalid; review the customer again")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("preview confirmation is invalid; review the customer again")
	}
	mac := hmac.New(sha256.New, s.previewKey[:])
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return errors.New("preview confirmation is invalid; review the customer again")
	}
	if err := json.Unmarshal(payload, destination); err != nil {
		return errors.New("preview confirmation is invalid; review the customer again")
	}
	if time.Now().After(destination.ExpiresAt) {
		return errors.New("preview expired; review the customer again")
	}
	return nil
}

func buildChangePreview(existing *customer.Customer, desired customer.Customer, plan networkplan.Plan) *changePreview {
	preview := &changePreview{Mode: "create", Creates: 1 + len(plan.Targets)*2}
	if existing == nil {
		preview.Summaries = []string{"Create customer and weekly schedule", fmt.Sprintf("Create %d target/task pairs", len(plan.Targets))}
		return preview
	}
	preview.Mode = "update"
	before, _ := networkplan.Build(networkplan.Input{CustomerName: existing.Name, Networks: networkInputsForWeb(existing.Networks)})
	preview.Unchanged = 1
	oldTargets := make(map[string]string, len(before.Targets))
	for _, target := range before.Targets {
		oldTargets[fmt.Sprintf("%s/%d", target.Class, target.Sequence)] = target.Hash
	}
	for _, target := range plan.Targets {
		key := fmt.Sprintf("%s/%d", target.Class, target.Sequence)
		if hash, found := oldTargets[key]; !found {
			preview.Creates += 2
		} else if hash != target.Hash {
			preview.Modifies += 2
		} else {
			preview.Unchanged += 2
		}
		delete(oldTargets, key)
	}
	preview.Trashes = len(oldTargets) * 2
	if existing.ScheduleWeekday != desired.ScheduleWeekday || existing.ScheduleMinute != desired.ScheduleMinute || existing.Timezone != desired.Timezone {
		preview.Modifies++
		preview.Unchanged--
	}
	preview.Summaries = []string{fmt.Sprintf("%d creates, %d changes, %d removals", preview.Creates, preview.Modifies, preview.Trashes)}
	return preview
}

func networkInputsForWeb(networks []customer.Network) []string {
	result := make([]string, 0, len(networks))
	for _, network := range networks {
		result = append(result, network.Prefix)
	}
	return result
}

func splitNetworkInputs(value string) []string {
	fields := strings.FieldsFunc(value, func(character rune) bool {
		return character == '\n' || character == '\r' || character == ',' || character == ';'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func selectedOption(options []gmp.Option, optionID string) (customer.Selection, error) {
	for _, option := range options {
		if option.ID == optionID {
			return customer.Selection{ID: option.ID, Name: option.Name}, nil
		}
	}
	return customer.Selection{}, fmt.Errorf("selected greenbone object %q is unavailable", optionID)
}

func (s *Server) apiPreview(response http.ResponseWriter, request *http.Request) {
	var payload struct {
		CustomerName string   `json:"customer_name"`
		Networks     []string `json:"networks"`
	}
	if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}
	plan, err := networkplan.Build(networkplan.Input{
		CustomerName: payload.CustomerName,
		Networks:     payload.Networks,
	})
	if err != nil {
		writeJSON(response, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(response, http.StatusOK, plan)
}
