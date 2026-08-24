package web

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"openvasconf/internal/id"
)

const (
	sessionCookieName     = "openvasconf_session"
	csrfCookieName        = "openvasconf_csrf"
	contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; " +
		"style-src 'self'; script-src 'self'; base-uri 'none'; " +
		"form-action 'self'; frame-ancestors 'none'"
)

type contextKey int

const csrfContextKey contextKey = iota + 1

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		response.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		response.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(response, request)
	})
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		token := ""
		if cookie, err := request.Cookie(csrfCookieName); err == nil {
			token = cookie.Value
		}
		if token == "" {
			generated, err := id.Token(32)
			if err != nil {
				http.Error(response, "unable to initialize request security", http.StatusInternalServerError)
				return
			}
			token = generated
			// codeql[go/cookie-secure-not-set]
			// #nosec G124 -- Secure is selected from TLS and trusted deployment configuration.
			http.SetCookie(response, &http.Cookie{
				Name:     csrfCookieName,
				Value:    token,
				Path:     "/",
				MaxAge:   86400,
				HttpOnly: true,
				Secure:   s.isSecure(request),
				SameSite: http.SameSiteStrictMode,
			})
		}
		request = request.WithContext(context.WithValue(request.Context(), csrfContextKey, token))
		if request.Method == http.MethodPost {
			request.Body = http.MaxBytesReader(response, request.Body, 1<<20)
			provided := request.Header.Get("X-CSRF-Token")
			if provided == "" {
				var err error
				if strings.HasPrefix(request.Header.Get("Content-Type"), "multipart/form-data") {
					// #nosec G120 -- MaxBytesReader caps the complete body at 1 MiB above.
					err = request.ParseMultipartForm(1 << 20)
				} else {
					err = request.ParseForm()
				}
				if err != nil {
					http.Error(response, "invalid request", http.StatusBadRequest)
					return
				}
				provided = request.Form.Get("csrf_token")
			}
			if !constantTimeEqual(token, provided) {
				http.Error(response, "invalid request token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(response, request)
	})
}

func constantTimeEqual(expected, actual string) bool {
	if len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func csrfToken(request *http.Request) string {
	token, _ := request.Context().Value(csrfContextKey).(string)
	return token
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(response, request, "/login", http.StatusSeeOther)
			return
		}
		valid, err := s.auth.Valid(request.Context(), cookie.Value)
		if err != nil {
			s.logger.Error("session validation failed", "error", err)
			http.Error(response, "service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if !valid {
			http.Redirect(response, request, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func (s *Server) isSecure(request *http.Request) bool {
	if s.secureCookies || request.TLS != nil {
		return true
	}
	return s.trustProxyTLSHeader && strings.EqualFold(
		request.Header.Get("X-Forwarded-Proto"),
		"https",
	)
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: make(map[string][]time.Time)}
}

func (l *loginLimiter) allowed(remoteAddress string, now time.Time) bool {
	host := remoteHost(remoteAddress)
	cutoff := now.Add(-15 * time.Minute)

	l.mu.Lock()
	defer l.mu.Unlock()

	recent := l.attempts[host][:0]
	for _, attempt := range l.attempts[host] {
		if attempt.After(cutoff) {
			recent = append(recent, attempt)
		}
	}
	l.attempts[host] = recent
	return len(recent) < 5
}

func (l *loginLimiter) failure(remoteAddress string, now time.Time) {
	host := remoteHost(remoteAddress)
	l.mu.Lock()
	l.attempts[host] = append(l.attempts[host], now)
	l.mu.Unlock()
}

func (l *loginLimiter) success(remoteAddress string) {
	host := remoteHost(remoteAddress)
	l.mu.Lock()
	delete(l.attempts, host)
	l.mu.Unlock()
}

func remoteHost(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return remoteAddress
	}
	return host
}
