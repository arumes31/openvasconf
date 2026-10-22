package web

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"net/netip"
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
		if s.servedOverHTTPS(request) {
			response.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
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
			generated, err := s.issueCSRFToken(response, request)
			if err != nil {
				http.Error(response, "unable to initialize request security", http.StatusInternalServerError)
				return
			}
			token = generated
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

// issueCSRFToken sets a fresh double-submit token cookie. Login and logout call
// it too, so a token planted before authentication does not survive it.
func (s *Server) issueCSRFToken(response http.ResponseWriter, request *http.Request) (string, error) {
	token, err := id.Token(32)
	if err != nil {
		return "", err
	}
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
	return token, nil
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
	return s.secureCookies || s.servedOverHTTPS(request)
}

// servedOverHTTPS reports whether the browser reached the service over TLS,
// either directly or through a trusted TLS-terminating proxy.
func (s *Server) servedOverHTTPS(request *http.Request) bool {
	if request.TLS != nil {
		return true
	}
	return s.trustProxyTLSHeader && strings.EqualFold(
		request.Header.Get("X-Forwarded-Proto"),
		"https",
	)
}

const (
	loginWindow = 15 * time.Minute
	// loginClientFailures is the failure budget of one client address (an IPv6
	// client is keyed by its /64) inside loginWindow.
	loginClientFailures = 5
	// loginGlobalFailures caps failures across all clients inside loginWindow,
	// so rotating source addresses cannot buy unlimited password guesses.
	loginGlobalFailures = 50
	// loginMaxClients bounds the per-client map; clients beyond it share one
	// overflow bucket until expired entries are swept.
	loginMaxClients    = 10000
	loginSweepInterval = time.Minute
	loginOverflowKey   = "overflow"
)

type loginLimiter struct {
	mu        sync.Mutex
	attempts  map[string][]time.Time
	global    []time.Time
	lastSweep time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: make(map[string][]time.Time)}
}

func (l *loginLimiter) allowed(client string, now time.Time) bool {
	cutoff := now.Add(-loginWindow)

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweep(now, cutoff)
	l.global = recentAttempts(l.global, cutoff)
	if len(l.global) >= loginGlobalFailures {
		return false
	}
	key := l.key(client)
	recent := recentAttempts(l.attempts[key], cutoff)
	if len(recent) == 0 {
		delete(l.attempts, key)
	} else {
		l.attempts[key] = recent
	}
	return len(recent) < loginClientFailures
}

func (l *loginLimiter) failure(client string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := l.key(client)
	l.attempts[key] = append(l.attempts[key], now)
	l.global = append(l.global, now)
}

func (l *loginLimiter) success(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.attempts, l.key(client))
}

// key returns the bucket for client, falling back to the shared overflow
// bucket when the map is full. Callers hold l.mu.
func (l *loginLimiter) key(client string) string {
	if _, ok := l.attempts[client]; ok || len(l.attempts) < loginMaxClients {
		return client
	}
	return loginOverflowKey
}

// sweep drops expired entries for every client at most once per
// loginSweepInterval. Callers hold l.mu.
func (l *loginLimiter) sweep(now, cutoff time.Time) {
	if now.Sub(l.lastSweep) < loginSweepInterval {
		return
	}
	l.lastSweep = now
	for key, attempts := range l.attempts {
		if recent := recentAttempts(attempts, cutoff); len(recent) == 0 {
			delete(l.attempts, key)
		} else {
			l.attempts[key] = recent
		}
	}
}

func recentAttempts(attempts []time.Time, cutoff time.Time) []time.Time {
	recent := attempts[:0]
	for _, attempt := range attempts {
		if attempt.After(cutoff) {
			recent = append(recent, attempt)
		}
	}
	return recent
}

// loginClient returns the rate-limit key for request. The rightmost
// X-Forwarded-For entry, which the reverse proxy itself appended, is used only
// when the deployment trusts its proxy; otherwise the TCP peer address is used.
// IPv6 clients are keyed by their /64 because one host usually controls a
// whole /64.
func (s *Server) loginClient(request *http.Request) string {
	host := remoteHost(request.RemoteAddr)
	if s.trustProxyClientIP {
		if forwarded := request.Header.Values("X-Forwarded-For"); len(forwarded) > 0 {
			entries := strings.Split(forwarded[len(forwarded)-1], ",")
			if candidate := strings.TrimSpace(entries[len(entries)-1]); candidate != "" {
				host = candidate
			}
		}
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	address = address.Unmap()
	if address.Is6() {
		prefix, _ := address.Prefix(64)
		return prefix.String()
	}
	return address.String()
}

func remoteHost(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return remoteAddress
	}
	return host
}
