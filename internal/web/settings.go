package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/gmp"
)

func (s *Server) settingsPage(response http.ResponseWriter, request *http.Request) {
	settings, err := s.repository.Settings(request.Context())
	if err != nil {
		s.internalError(response, err)
		return
	}
	options, optionsError := s.greenbone.Options(request.Context())
	data := pageData{
		Title:         "Greenbone settings",
		Authenticated: true,
		Settings:      settings,
		Options:       options,
		Notice:        connectionNotice(request.URL.Query().Get("connection")),
	}
	if optionsError != nil {
		data.GreenboneError = optionsError.Error()
	}
	s.render(response, request, "settings.html", data)
}

func (s *Server) settingsUpdate(response http.ResponseWriter, request *http.Request) {
	settings, err := s.repository.Settings(request.Context())
	if err != nil {
		s.internalError(response, err)
		return
	}
	options, err := s.greenbone.Options(request.Context())
	if err != nil {
		s.renderSettingsError(response, request, settings, gmp.Options{}, err)
		return
	}
	settings.Scanner, err = selectedOption(options.Scanners, request.PostForm.Get("scanner_id"))
	if err != nil {
		s.renderSettingsError(response, request, settings, options, err)
		return
	}
	settings.ScanConfig, err = selectedOption(options.ScanConfigs, request.PostForm.Get("scan_config_id"))
	if err != nil {
		s.renderSettingsError(response, request, settings, options, err)
		return
	}
	settings.PortList, err = selectedOption(options.PortLists, request.PostForm.Get("port_list_id"))
	if err != nil {
		s.renderSettingsError(response, request, settings, options, err)
		return
	}
	settings.Timezone = request.PostForm.Get("timezone")
	if _, err := time.LoadLocation(settings.Timezone); err != nil {
		s.renderSettingsError(
			response,
			request,
			settings,
			options,
			fmt.Errorf("invalid timezone %q", settings.Timezone),
		)
		return
	}
	weekdayValues := request.PostForm["schedule_weekday"]
	if len(weekdayValues) > 0 || request.PostForm.Get("schedule_start") != "" || request.PostForm.Get("schedule_end") != "" {
		weekdays := make([]int, 0, 4)
		for _, raw := range weekdayValues {
			weekday, parseErr := strconv.Atoi(raw)
			if parseErr != nil {
				s.renderSettingsError(response, request, settings, options, errors.New("invalid allowed weekday"))
				return
			}
			weekdays = append(weekdays, weekday)
		}
		startMinute, err := parseClockMinute(request.PostForm.Get("schedule_start"))
		if err != nil {
			s.renderSettingsError(response, request, settings, options, err)
			return
		}
		endMinute, err := parseClockMinute(request.PostForm.Get("schedule_end"))
		if err != nil {
			s.renderSettingsError(response, request, settings, options, err)
			return
		}
		settings.SchedulePolicy = customer.SchedulePolicy{Weekdays: weekdays, StartMinute: startMinute, EndMinute: endMinute}
		if err := customer.ValidateSchedulePolicy(settings.SchedulePolicy); err != nil {
			s.renderSettingsError(response, request, settings, options, err)
			return
		}
	}
	if err := s.repository.UpdateSettings(request.Context(), settings); err != nil {
		s.renderSettingsError(response, request, settings, options, err)
		return
	}
	s.syncer.Trigger()
	http.Redirect(response, request, "/settings", http.StatusSeeOther)
}

func parseClockMinute(value string) (int, error) {
	parsed, err := time.Parse("15:04", strings.TrimSpace(value))
	if err != nil {
		return 0, errors.New("schedule times must use HH:MM")
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}

func connectionNotice(value string) string {
	switch value {
	case "ok":
		return "Greenbone connection, feeds, and task queries succeeded."
	case "failed":
		return "Greenbone connection test failed. Check the GMP socket and feed state."
	default:
		return ""
	}
}

func (s *Server) renderSettingsError(
	response http.ResponseWriter,
	request *http.Request,
	settings customer.Settings,
	options gmp.Options,
	settingsError error,
) {
	s.render(response, request, "settings.html", pageData{
		Title:         "Greenbone settings",
		Authenticated: true,
		Settings:      settings,
		Options:       options,
		Error:         settingsError.Error(),
	})
}
