package web

import (
	"context"
	"crypto/rand"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/gmp"
	"openvasconf/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Repository interface {
	Ping(ctx context.Context) error
	Settings(ctx context.Context) (customer.Settings, error)
	UpdateSettings(ctx context.Context, settings customer.Settings) error
	Customer(ctx context.Context, customerID string) (customer.Customer, error)
	Customers(ctx context.Context, includeDeleted bool) ([]customer.Customer, error)
	ListCustomers(ctx context.Context, query store.CustomerQuery) ([]customer.Customer, error)
	CreateCustomer(ctx context.Context, value customer.Customer) error
	UpdateCustomer(ctx context.Context, value customer.Customer) error
	SoftDeleteCustomer(ctx context.Context, customerID string) error
	ManagedResources(ctx context.Context, customerID string) ([]store.ManagedResource, error)
	ReconcileRuns(ctx context.Context, customerID string, limit int) ([]store.ReconcileRun, error)
	ApplyImport(ctx context.Context, settings customer.Settings, customers []customer.Customer) error
	AuditEvents(ctx context.Context, limit int) ([]store.AuditEvent, error)
}

type Authenticator interface {
	Login(ctx context.Context, username, password string) (string, time.Time, error)
	Valid(ctx context.Context, token string) (bool, error)
	Logout(ctx context.Context, token string) error
}

type Greenbone interface {
	Ping(ctx context.Context) (string, error)
	Options(ctx context.Context) (gmp.Options, error)
}

type Syncer interface {
	Trigger()
}

type Options struct {
	Repository          Repository
	Auth                Authenticator
	Greenbone           Greenbone
	Syncer              Syncer
	Logger              *slog.Logger
	SecureCookies       bool
	TrustProxyTLSHeader bool
}

type Server struct {
	repository          Repository
	auth                Authenticator
	greenbone           Greenbone
	syncer              Syncer
	logger              *slog.Logger
	templates           *template.Template
	secureCookies       bool
	trustProxyTLSHeader bool
	loginLimiter        *loginLimiter
	previewKey          [32]byte
}

func New(options Options) (*Server, error) {
	var previewKey [32]byte
	if _, err := rand.Read(previewKey[:]); err != nil {
		return nil, err
	}
	templates, err := template.New("pages").Funcs(template.FuncMap{
		"weekday":    customer.WeekdayName,
		"minuteTime": customer.MinuteTime,
		"selected": func(current, candidate string) bool {
			return current == candidate
		},
		"list": func(values ...string) []string { return values },
		"containsInt": func(values []int, candidate int) bool {
			for _, value := range values {
				if value == candidate {
					return true
				}
			}
			return false
		},
		"percent": func(value, total uint64) int {
			if total == 0 {
				return 0
			}
			return int(value * 100 / total)
		},
		"nextScan": func(value customer.Customer) string {
			next, nextErr := value.NextSchedule(time.Now())
			if nextErr != nil {
				return "unavailable"
			}
			return next.Format("Mon 2006-01-02 15:04 MST")
		},
		"duration": func(start time.Time, finish *time.Time) string {
			end := time.Now()
			if finish != nil {
				end = *finish
			}
			return end.Sub(start).Round(time.Millisecond).String()
		},
		"outOfPolicy": func(value customer.Customer, settings customer.Settings) bool {
			allowed := false
			for _, weekday := range settings.SchedulePolicy.Weekdays {
				allowed = allowed || weekday == value.ScheduleWeekday
			}
			return !allowed || value.ScheduleMinute < settings.SchedulePolicy.StartMinute ||
				value.ScheduleMinute > settings.SchedulePolicy.EndMinute
		},
		"effectiveScanner": func(value customer.Customer, settings customer.Settings) string {
			return value.EffectiveScanner(settings).Name
		},
		"effectiveConfig": func(value customer.Customer, settings customer.Settings) string {
			return value.EffectiveScanConfig(settings).Name
		},
		"effectivePorts": func(value customer.Customer, settings customer.Settings) string {
			return value.EffectivePortList(settings).Name
		},
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{
		repository:          options.Repository,
		auth:                options.Auth,
		greenbone:           options.Greenbone,
		syncer:              options.Syncer,
		logger:              options.Logger,
		templates:           templates,
		secureCookies:       options.SecureCookies,
		trustProxyTLSHeader: options.TrustProxyTLSHeader,
		loginLimiter:        newLoginLimiter(),
		previewKey:          previewKey,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.healthLive)
	mux.HandleFunc("GET /health/ready", s.healthReady)
	mux.Handle("GET /static/", http.FileServerFS(assets))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)

	mux.Handle("GET /", s.requireAuth(http.HandlerFunc(s.dashboard)))
	mux.Handle("POST /logout", s.requireAuth(http.HandlerFunc(s.logout)))
	mux.Handle("GET /customers/new", s.requireAuth(http.HandlerFunc(s.customerNew)))
	mux.Handle("POST /customers", s.requireAuth(http.HandlerFunc(s.customerCreate)))
	mux.Handle("POST /customers/preview", s.requireAuth(http.HandlerFunc(s.customerPreviewNew)))
	mux.Handle("GET /customers/{id}", s.requireAuth(http.HandlerFunc(s.customerEdit)))
	mux.Handle("POST /customers/{id}", s.requireAuth(http.HandlerFunc(s.customerUpdate)))
	mux.Handle("POST /customers/{id}/preview", s.requireAuth(http.HandlerFunc(s.customerPreviewExisting)))
	mux.Handle("POST /customers/{id}/delete", s.requireAuth(http.HandlerFunc(s.customerDelete)))
	mux.Handle("POST /customers/{id}/clone", s.requireAuth(http.HandlerFunc(s.customerClone)))
	mux.Handle("POST /customers/{id}/randomize", s.requireAuth(http.HandlerFunc(s.customerRandomize)))
	mux.Handle("POST /customers/{id}/sync", s.requireAuth(http.HandlerFunc(s.customerSync)))
	mux.Handle("POST /customers/{id}/retry", s.requireAuth(http.HandlerFunc(s.customerSync)))
	mux.Handle("GET /customers/{id}/history", s.requireAuth(http.HandlerFunc(s.customerHistory)))
	mux.Handle("GET /settings", s.requireAuth(http.HandlerFunc(s.settingsPage)))
	mux.Handle("POST /settings", s.requireAuth(http.HandlerFunc(s.settingsUpdate)))
	mux.Handle("POST /settings/test", s.requireAuth(http.HandlerFunc(s.settingsTest)))
	mux.Handle("POST /sync", s.requireAuth(http.HandlerFunc(s.synchronize)))
	mux.Handle("POST /sync-selected", s.requireAuth(http.HandlerFunc(s.synchronizeSelected)))
	mux.Handle("GET /export", s.requireAuth(http.HandlerFunc(s.exportConfiguration)))
	mux.Handle("GET /import", s.requireAuth(http.HandlerFunc(s.importPage)))
	mux.Handle("POST /import/preview", s.requireAuth(http.HandlerFunc(s.importPreview)))
	mux.Handle("POST /import/apply", s.requireAuth(http.HandlerFunc(s.importApply)))
	mux.Handle("GET /api/status", s.requireAuth(http.HandlerFunc(s.apiStatus)))
	mux.Handle("POST /api/preview", s.requireAuth(http.HandlerFunc(s.apiPreview)))
	mux.Handle("GET /api/options", s.requireAuth(http.HandlerFunc(s.apiOptions)))
	mux.Handle("GET /api/operations", s.requireAuth(http.HandlerFunc(s.apiOperations)))
	mux.Handle("GET /api/customers/{id}/progress", s.requireAuth(http.HandlerFunc(s.apiCustomerProgress)))
	mux.Handle("GET /api/customers/{id}/drift", s.requireAuth(http.HandlerFunc(s.apiCustomerDrift)))
	mux.Handle("POST /customers/{id}/tasks/{kind}/{class}/{sequence}/start", s.requireAuth(http.HandlerFunc(s.startScan)))

	return s.securityHeaders(s.csrf(mux))
}
