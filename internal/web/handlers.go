package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"openvasconf/internal/auth"
	"openvasconf/internal/store"
)

func (s *Server) healthLive(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{"status": "live"})
}

func (s *Server) healthReady(response http.ResponseWriter, request *http.Request) {
	result := s.status(request.Context())
	status := http.StatusOK
	if !result.Database || !result.Greenbone {
		status = http.StatusServiceUnavailable
	}
	writeJSON(response, status, result)
}

func (s *Server) loginPage(response http.ResponseWriter, request *http.Request) {
	s.render(response, request, "login.html", pageData{Title: "Operator login"})
}

func (s *Server) login(response http.ResponseWriter, request *http.Request) {
	if !s.loginLimiter.allowed(request.RemoteAddr, time.Now()) {
		s.render(response, request, "login.html", pageData{
			Title: "Operator login",
			Error: "Too many login attempts. Wait before trying again.",
		})
		return
	}
	token, expiresAt, err := s.auth.Login(
		request.Context(),
		request.PostForm.Get("username"),
		request.PostForm.Get("password"),
	)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		s.loginLimiter.failure(request.RemoteAddr, time.Now())
		s.render(response, request, "login.html", pageData{
			Title: "Operator login",
			Error: "Invalid username or password.",
		})
		return
	}
	if err != nil {
		s.logger.Error("login failed", "error", err)
		http.Error(response, "service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	s.loginLimiter.success(request.RemoteAddr)
	// codeql[go/cookie-secure-not-set]
	// #nosec G124 -- Secure is selected from TLS and trusted deployment configuration.
	http.SetCookie(response, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   s.isSecure(request),
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

func (s *Server) logout(response http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie(sessionCookieName); err == nil {
		if err := s.auth.Logout(request.Context(), cookie.Value); err != nil {
			s.logger.Error("logout failed", "error", err)
		}
	}
	// codeql[go/cookie-secure-not-set]
	// #nosec G124 -- this expires the cookie using the same deployment policy.
	http.SetCookie(response, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.isSecure(request),
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(response, request, "/login", http.StatusSeeOther)
}

func (s *Server) dashboard(response http.ResponseWriter, request *http.Request) {
	query := store.CustomerQuery{
		Search:     request.URL.Query().Get("q"),
		Status:     request.URL.Query().Get("status"),
		Sort:       request.URL.Query().Get("sort"),
		Descending: strings.EqualFold(request.URL.Query().Get("order"), "desc"),
	}
	customers, err := s.repository.ListCustomers(request.Context(), query)
	if err != nil {
		s.internalError(response, err)
		return
	}
	events, err := s.repository.AuditEvents(request.Context(), 20)
	if err != nil {
		s.internalError(response, err)
		return
	}
	settings, err := s.repository.Settings(request.Context())
	if err != nil {
		s.internalError(response, err)
		return
	}
	version, greenboneError := s.greenboneStatus(request.Context())
	updateStatus, _ := s.updateStatus(request.Context())
	data := pageData{
		Title:            "Scan operations",
		Authenticated:    true,
		Customers:        customers,
		Events:           events,
		Settings:         settings,
		GreenboneVersion: version,
		Query:            query,
		QueryValues:      request.URL.Query(),
		Notice:           noticeText(request.URL.Query().Get("notice")),
		UpdateStatus:     updateStatus,
	}
	if greenboneError != nil {
		data.GreenboneError = greenboneError.Error()
	}
	s.render(response, request, "dashboard.html", data)
}

func noticeText(value string) string {
	switch value {
	case "sync-requested":
		return "Full reconciliation requested."
	case "scan-started":
		return "Scan start requested."
	case "scan-stop-requested":
		return "Stop requested; the displayed state updates once Greenbone reports it."
	case "customer-sync-requested":
		return "Customer reconciliation requested."
	case "bulk-sync-requested":
		return "Selected customers queued for reconciliation."
	case "select-customers":
		return "Select at least one customer."
	case "import-applied":
		return "Imported desired state applied and reconciliation queued."
	case "report-sync-requested":
		return "Report synchronization requested; new snapshots appear after the next cycle."
	case "annotation-saved":
		return "Finding annotation saved; it applies to future snapshots of this customer too."
	default:
		return ""
	}
}

func (s *Server) synchronize(response http.ResponseWriter, request *http.Request) {
	s.syncer.Trigger()
	http.Redirect(response, request, "/?notice=sync-requested", http.StatusSeeOther)
}

type statusResponse struct {
	Database         bool   `json:"database"`
	Greenbone        bool   `json:"greenbone"`
	GreenboneVersion string `json:"greenbone_version,omitempty"`
	Error            string `json:"error,omitempty"`
}

func (s *Server) status(ctx context.Context) statusResponse {
	result := statusResponse{Database: true}
	if err := s.repository.Ping(ctx); err != nil {
		result.Database = false
		result.Error = "database unavailable"
		return result
	}
	version, err := s.greenboneStatus(ctx)
	if err != nil {
		result.Error = "greenbone unavailable"
		return result
	}
	result.Greenbone = true
	result.GreenboneVersion = version
	return result
}

func (s *Server) greenboneStatus(ctx context.Context) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.greenbone.Ping(bounded)
}

func (s *Server) apiStatus(response http.ResponseWriter, request *http.Request) {
	writeJSON(response, http.StatusOK, s.status(request.Context()))
}

func (s *Server) apiOptions(response http.ResponseWriter, request *http.Request) {
	options, err := s.greenbone.Options(request.Context())
	if err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{
			"error": "greenbone options unavailable",
		})
		return
	}
	writeJSON(response, http.StatusOK, options)
}

func (s *Server) internalError(response http.ResponseWriter, err error) {
	s.logger.Error("web request failed", "error", err)
	http.Error(response, "unexpected server error", http.StatusInternalServerError)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
