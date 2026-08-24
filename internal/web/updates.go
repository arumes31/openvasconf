package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openvasconf/internal/id"
	"openvasconf/internal/store"
	"openvasconf/internal/updater"
)

func (s *Server) updatesPage(response http.ResponseWriter, request *http.Request) {
	policy, err := s.repository.UpdatePolicy(request.Context())
	if err != nil {
		s.internalError(response, err)
		return
	}
	status, statusErr := s.updateStatus(request.Context())
	data := pageData{
		Title:         "Greenbone updates",
		Authenticated: true,
		UpdatePolicy:  policy,
		UpdateStatus:  status,
		Notice:        updateNotice(request.URL.Query().Get("notice")),
	}
	if statusErr != nil {
		data.UpdaterError = "The updater helper is unavailable. Monitoring through GMP remains active, but update controls are disabled."
	}
	s.render(response, request, "updates.html", data)
}

func (s *Server) updatesSettings(response http.ResponseWriter, request *http.Request) {
	policy, err := updatePolicyFromForm(request)
	if err != nil {
		s.renderUpdateError(response, request, updater.Policy{}, err)
		return
	}
	if err := s.repository.SaveUpdatePolicy(request.Context(), policy); err != nil {
		s.renderUpdateError(response, request, policy, err)
		return
	}
	if err := s.repository.AddAuditEvent(request.Context(), store.AuditEvent{
		Action: "configure", ResourceKind: "updater", ResourceName: "schedule",
		Detail: "admin updated feed and stack maintenance policy",
	}); err != nil {
		s.logger.Error("recording updater policy audit failed", "error", err)
	}
	if s.updater == nil {
		http.Redirect(response, request, "/updates?notice=saved-offline", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	if err := s.updater.Configure(ctx, policy); err != nil {
		s.logger.Warn("applying updater policy failed", "error", err)
		http.Redirect(response, request, "/updates?notice=saved-offline", http.StatusSeeOther)
		return
	}
	http.Redirect(response, request, "/updates?notice=saved", http.StatusSeeOther)
}

func (s *Server) updatesCheck(response http.ResponseWriter, request *http.Request) {
	s.triggerUpdate(response, request, updater.KindCheck)
}

func (s *Server) updatesFeed(response http.ResponseWriter, request *http.Request) {
	s.triggerUpdate(response, request, updater.KindFeed)
}

func (s *Server) updatesStack(response http.ResponseWriter, request *http.Request) {
	s.triggerUpdate(response, request, updater.KindStack)
}

func (s *Server) triggerUpdate(response http.ResponseWriter, request *http.Request, kind updater.Kind) {
	if s.updater == nil {
		http.Redirect(response, request, "/updates?notice=offline", http.StatusSeeOther)
		return
	}
	key, err := id.New()
	if err != nil {
		s.internalError(response, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	operation, err := s.updater.Trigger(ctx, kind, updater.TriggerRequest{
		IdempotencyKey: key,
		Trigger:        updater.TriggerAdmin,
	})
	if err != nil {
		s.logger.Warn("requesting updater operation failed", "kind", kind, "error", err)
		notice := "failed"
		if errors.Is(err, updater.ErrBusy) {
			notice = "busy"
		} else if errors.Is(err, updater.ErrPaused) {
			notice = "paused"
		} else if errors.Is(err, updater.ErrUnavailable) {
			notice = "offline"
		}
		http.Redirect(response, request, "/updates?notice="+notice, http.StatusSeeOther)
		return
	}
	if err := s.repository.AddAuditEvent(request.Context(), store.AuditEvent{
		Action:       "start",
		ResourceKind: "updater",
		ResourceName: string(kind),
		Detail:       "admin requested operation " + operation.ID,
	}); err != nil {
		s.logger.Error("recording updater operation audit failed", "error", err)
	}
	http.Redirect(response, request, "/updates?notice=started", http.StatusSeeOther)
}

func (s *Server) updatesAcknowledge(response http.ResponseWriter, request *http.Request) {
	if s.updater == nil {
		http.Redirect(response, request, "/updates?notice=offline", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	if err := s.updater.Acknowledge(ctx); err != nil {
		s.logger.Warn("acknowledging updater pause failed", "error", err)
		http.Redirect(response, request, "/updates?notice=failed", http.StatusSeeOther)
		return
	}
	if err := s.repository.AddAuditEvent(request.Context(), store.AuditEvent{
		Action: "acknowledge", ResourceKind: "updater", ResourceName: "stack",
		Detail: "admin acknowledged the automatic-upgrade pause",
	}); err != nil {
		s.logger.Error("recording updater acknowledgement audit failed", "error", err)
	}
	http.Redirect(response, request, "/updates?notice=acknowledged", http.StatusSeeOther)
}

func (s *Server) apiUpdatesStatus(response http.ResponseWriter, request *http.Request) {
	status, err := s.updateStatus(request.Context())
	if err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]any{
			"available": false,
			"error":     "updater helper unavailable",
		})
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (s *Server) updateStatus(ctx context.Context) (*updater.Status, error) {
	if s.updater == nil {
		return nil, updater.ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	status, err := s.updater.Status(bounded)
	if err != nil {
		return nil, err
	}
	if status.ProtocolVersion != updater.ProtocolVersion {
		return nil, fmt.Errorf("updater protocol %q is incompatible", status.ProtocolVersion)
	}
	return &status, nil
}

func updatePolicyFromForm(request *http.Request) (updater.Policy, error) {
	feedMinute, err := parseClockMinute(request.PostForm.Get("feed_time"))
	if err != nil {
		return updater.Policy{}, fmt.Errorf("feed time: %w", err)
	}
	stackMinute, err := parseClockMinute(request.PostForm.Get("stack_time"))
	if err != nil {
		return updater.Policy{}, fmt.Errorf("maintenance start: %w", err)
	}
	stackWeekday, err := strconv.Atoi(strings.TrimSpace(request.PostForm.Get("stack_weekday")))
	if err != nil {
		return updater.Policy{}, errors.New("maintenance weekday is invalid")
	}
	window, err := strconv.Atoi(strings.TrimSpace(request.PostForm.Get("stack_window_minutes")))
	if err != nil {
		return updater.Policy{}, errors.New("maintenance window is invalid")
	}
	retention, err := strconv.Atoi(strings.TrimSpace(request.PostForm.Get("backup_retention")))
	if err != nil {
		return updater.Policy{}, errors.New("backup retention is invalid")
	}
	verification, err := strconv.Atoi(strings.TrimSpace(request.PostForm.Get("verification_timeout_minutes")))
	if err != nil {
		return updater.Policy{}, errors.New("verification timeout is invalid")
	}
	policy := updater.Policy{
		FeedEnabled:               request.PostForm.Get("feed_enabled") == "on",
		FeedMinute:                feedMinute,
		StackEnabled:              request.PostForm.Get("stack_enabled") == "on",
		StackWeekday:              stackWeekday,
		StackStartMinute:          stackMinute,
		StackWindowMinutes:        window,
		Timezone:                  strings.TrimSpace(request.PostForm.Get("update_timezone")),
		BackupRetention:           retention,
		VerificationTimeoutMinute: verification,
	}
	if err := policy.Validate(); err != nil {
		return updater.Policy{}, err
	}
	return policy, nil
}

func (s *Server) renderUpdateError(
	response http.ResponseWriter,
	request *http.Request,
	policy updater.Policy,
	updateErr error,
) {
	if policy.Timezone == "" {
		stored, err := s.repository.UpdatePolicy(request.Context())
		if err == nil {
			policy = stored
		}
	}
	status, _ := s.updateStatus(request.Context())
	s.render(response, request, "updates.html", pageData{
		Title:         "Greenbone updates",
		Authenticated: true,
		UpdatePolicy:  policy,
		UpdateStatus:  status,
		Error:         updateErr.Error(),
	})
}

func updateNotice(value string) string {
	switch value {
	case "saved":
		return "Update policy saved and applied to the helper."
	case "saved-offline":
		return "Update policy saved. The helper is offline and will need the policy applied when it returns."
	case "started":
		return "Update operation queued. Progress appears below."
	case "busy":
		return "Another update operation is already active."
	case "paused":
		return "Stack automation is paused after a rollback or recovery failure. Review and acknowledge it first."
	case "offline":
		return "The updater helper is unavailable."
	case "acknowledged":
		return "Automatic stack upgrades resumed."
	case "failed":
		return "The updater rejected the operation. Review helper status and logs."
	default:
		return ""
	}
}
