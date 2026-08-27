package web

import (
	"context"
	"crypto/rand"
	"embed"
	"html/template"
	"log/slog"
	"math/bits"
	"net/http"
	"strings"
	"sync"
	"time"

	"openvasconf/internal/customer"
	"openvasconf/internal/gmp"
	"openvasconf/internal/store"
	"openvasconf/internal/updater"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Repository interface {
	Ping(ctx context.Context) error
	Settings(ctx context.Context) (customer.Settings, error)
	UpdateSettings(ctx context.Context, settings customer.Settings) error
	UpdatePolicy(ctx context.Context) (updater.Policy, error)
	SaveUpdatePolicy(ctx context.Context, policy updater.Policy) error
	AddAuditEvent(ctx context.Context, event store.AuditEvent) error
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
	ListReportSnapshots(ctx context.Context, customerID string, limit int) ([]store.ReportSnapshot, error)
	ReportSnapshot(ctx context.Context, id int64) (store.ReportSnapshot, error)
	ReportFindings(ctx context.Context, snapshotID int64) ([]store.FindingSnapshot, error)
	PreviousImportedSnapshot(ctx context.Context, snapshot store.ReportSnapshot) (store.ReportSnapshot, error)
	ReportTrend(ctx context.Context, customerID string, limit int) ([]store.ReportSnapshot, error)
	FirstSeenForTask(ctx context.Context, customerID, taskID string, fingerprints []string) (map[string]time.Time, error)
	UpsertAnnotation(ctx context.Context, annotation store.FindingAnnotation) error
	AnnotationsForCustomer(ctx context.Context, customerID string) (map[string]store.FindingAnnotation, error)
	AnnotationsForTask(ctx context.Context, customerID, taskID string) (map[string]store.FindingAnnotation, error)
	CurrentFindings(ctx context.Context, filter store.FindingQuery) ([]store.CurrentFinding, int, error)
	CurrentFindingMetrics(ctx context.Context) (store.FindingMetrics, error)
	UpdateHookwiseSettings(ctx context.Context, settings customer.HookwiseSettings) error
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

type hookwiseManager interface {
	Trigger()
	Save(ctx context.Context, enabled bool, endpoint, token string) error
	Test(ctx context.Context) error
	Retry(ctx context.Context) error
	Stats(ctx context.Context) (store.HookwiseStats, error)
	Health(ctx context.Context) (state, detail, guidance, link string)
}

type Options struct {
	Repository          Repository
	Auth                Authenticator
	Greenbone           Greenbone
	Syncer              Syncer
	Reports             reportHealth
	Updater             updater.Manager
	Hookwise            hookwiseManager
	Logger              *slog.Logger
	SecureCookies       bool
	TrustProxyTLSHeader bool
	// Export limits; zero values select the defaults (100k rows, 50MB).
	ExportMaxRows  int
	ExportMaxBytes int64
}

const (
	defaultExportMaxRows  = 100000
	defaultExportMaxBytes = 50 << 20
)

type Server struct {
	repository          Repository
	auth                Authenticator
	greenbone           Greenbone
	syncer              Syncer
	reports             reportHealth
	updater             updater.Manager
	hookwise            hookwiseManager
	logger              *slog.Logger
	templates           *template.Template
	secureCookies       bool
	trustProxyTLSHeader bool
	exportMaxRows       int
	exportMaxBytes      int64
	loginLimiter        *loginLimiter
	previewKey          [32]byte
	healthMu            sync.Mutex
	healthCache         *healthStrip
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
		"add":  func(left, right int) int { return left + right },
		"sub":  func(left, right int) int { return left - right },
		"containsInt": func(values []int, candidate int) bool {
			for _, value := range values {
				if value == candidate {
					return true
				}
			}
			return false
		},
		"percent": func(value, total uint64) uint64 {
			if total == 0 {
				return 0
			}
			if value >= total {
				return 100
			}
			high, low := bits.Mul64(value, 100)
			percent, _ := bits.Div64(high, low, total)
			return percent
		},
		"taskActive": func(status string) bool {
			switch strings.ToLower(status) {
			case "running", "requested", "queued", "processing":
				return true
			}
			return false
		},
		"severityClass":    severityClass,
		"importStateClass": importStateClass,
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
	exportMaxRows := options.ExportMaxRows
	if exportMaxRows <= 0 {
		exportMaxRows = defaultExportMaxRows
	}
	exportMaxBytes := options.ExportMaxBytes
	if exportMaxBytes <= 0 {
		exportMaxBytes = defaultExportMaxBytes
	}
	return &Server{
		repository:          options.Repository,
		auth:                options.Auth,
		greenbone:           options.Greenbone,
		syncer:              options.Syncer,
		reports:             options.Reports,
		updater:             options.Updater,
		hookwise:            options.Hookwise,
		logger:              options.Logger,
		templates:           templates,
		secureCookies:       options.SecureCookies,
		trustProxyTLSHeader: options.TrustProxyTLSHeader,
		exportMaxRows:       exportMaxRows,
		exportMaxBytes:      exportMaxBytes,
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
	mux.Handle("GET /updates", s.requireAuth(http.HandlerFunc(s.updatesPage)))
	mux.Handle("POST /updates/settings", s.requireAuth(http.HandlerFunc(s.updatesSettings)))
	mux.Handle("POST /updates/check", s.requireAuth(http.HandlerFunc(s.updatesCheck)))
	mux.Handle("POST /updates/feed", s.requireAuth(http.HandlerFunc(s.updatesFeed)))
	mux.Handle("POST /updates/stack", s.requireAuth(http.HandlerFunc(s.updatesStack)))
	mux.Handle("POST /updates/acknowledge", s.requireAuth(http.HandlerFunc(s.updatesAcknowledge)))
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
	mux.Handle("GET /api/updates/status", s.requireAuth(http.HandlerFunc(s.apiUpdatesStatus)))
	mux.Handle("GET /api/customers/{id}/progress", s.requireAuth(http.HandlerFunc(s.apiCustomerProgress)))
	mux.Handle("GET /api/customers/{id}/drift", s.requireAuth(http.HandlerFunc(s.apiCustomerDrift)))
	mux.Handle("POST /customers/{id}/tasks/{kind}/{class}/{sequence}/start", s.requireAuth(http.HandlerFunc(s.startScan)))
	mux.Handle("POST /customers/{id}/tasks/{kind}/{class}/{sequence}/stop", s.requireAuth(http.HandlerFunc(s.stopScan)))
	mux.Handle("GET /reports", s.requireAuth(http.HandlerFunc(s.reportsList)))
	mux.Handle("GET /findings", s.requireAuth(http.HandlerFunc(s.findingsList)))
	mux.Handle("POST /findings/state", s.requireAuth(http.HandlerFunc(s.findingStateUpdate)))
	mux.Handle("POST /reports/refresh", s.requireAuth(http.HandlerFunc(s.reportsRefresh)))
	mux.Handle("GET /reports/compare", s.requireAuth(http.HandlerFunc(s.reportCompare)))
	mux.Handle("GET /reports/{id}", s.requireAuth(http.HandlerFunc(s.reportDetail)))
	mux.Handle("GET /reports/{id}/export", s.requireAuth(http.HandlerFunc(s.reportExport)))
	mux.Handle("POST /reports/{id}/findings/annotate", s.requireAuth(http.HandlerFunc(s.reportAnnotate)))
	mux.Handle("POST /settings/hookwise", s.requireAuth(http.HandlerFunc(s.hookwiseSettingsUpdate)))
	mux.Handle("POST /settings/hookwise/test", s.requireAuth(http.HandlerFunc(s.hookwiseSettingsTest)))
	mux.Handle("POST /settings/hookwise/retry", s.requireAuth(http.HandlerFunc(s.hookwiseRetry)))

	return s.securityHeaders(s.csrf(mux))
}
