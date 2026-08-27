package web

import (
	"context"
	"time"

	"openvasconf/internal/gmp"
	"openvasconf/internal/store"
)

const healthCacheTTL = 15 * time.Second

type healthStrip struct {
	Level      string
	Summary    string
	CheckedAt  time.Time
	Components []healthComponent
}

type healthComponent struct {
	Name     string
	State    string
	Detail   string
	Guidance string
	Link     string
}

// reportHealth is implemented by the report synchronization service to
// contribute its component to the health strip. The plain-string signature
// lets any package provide an implementation.
type reportHealth interface {
	ReportHealth(ctx context.Context) (state, detail, guidance, link string)
}

func statusErrorQuery() store.CustomerQuery {
	return store.CustomerQuery{Status: "error", Limit: 1}
}

func (s *Server) health(ctx context.Context) healthStrip {
	s.healthMu.Lock()
	cached := s.healthCache
	s.healthMu.Unlock()
	if cached != nil && time.Since(cached.CheckedAt) < healthCacheTTL {
		return *cached
	}

	strip := s.probeHealth(ctx)
	s.healthMu.Lock()
	s.healthCache = &strip
	s.healthMu.Unlock()
	return strip
}

func (s *Server) probeHealth(ctx context.Context) healthStrip {
	probe, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	components := make([]healthComponent, 0, 5)

	database := healthComponent{Name: "Database", State: "ok", Detail: "SQLite repository reachable"}
	if err := s.repository.Ping(probe); err != nil {
		database.State = "down"
		database.Detail = "database unavailable"
		database.Guidance = "Check the database path, file permissions, and disk space, then restart the service."
	}
	components = append(components, database)

	greenbone := healthComponent{
		Name:  "Greenbone",
		State: "ok",
		Link:  "/settings",
	}
	version, err := s.greenboneStatus(probe)
	if err != nil {
		greenbone.State = "down"
		greenbone.Detail = "GMP connection failed"
		greenbone.Guidance = "Verify the gvmd socket path and credentials, then use Test Greenbone connection."
	} else {
		greenbone.Detail = "GMP reachable, version " + version
	}
	components = append(components, greenbone)

	feeds := healthComponent{
		Name:  "Feeds",
		State: "unknown",
		Link:  "/settings",
	}
	if operations, ok := s.greenbone.(operationalGreenbone); ok && greenbone.State == "ok" {
		feedList, feedErr := operations.Feeds(probe)
		switch {
		case feedErr != nil:
			feeds.State = "degraded"
			feeds.Detail = "feed status unavailable"
			feeds.Guidance = "Check the Greenbone feed containers and rerun the connection test."
		case len(feedList) == 0:
			feeds.State = "degraded"
			feeds.Detail = "no feeds reported"
			feeds.Guidance = "Wait for the initial feed sync to finish before scheduling scans."
		default:
			feeds = summarizeFeeds(feedList)
		}
	} else if greenbone.State != "ok" {
		feeds.Detail = "not queried while Greenbone is down"
	} else {
		feeds.Detail = "feed queries unsupported"
	}
	components = append(components, feeds)

	reconciliation := healthComponent{Name: "Reconciliation", State: "ok", Detail: "no failed customers", Link: "/?status=error"}
	failed, err := s.repository.ListCustomers(probe, statusErrorQuery())
	switch {
	case err != nil:
		reconciliation.State = "degraded"
		reconciliation.Detail = "customer state unavailable"
		reconciliation.Guidance = "Check the service logs for repository errors."
	case len(failed) > 0:
		reconciliation.State = "degraded"
		reconciliation.Detail = "customers in error state"
		reconciliation.Guidance = "Open the filtered customer list and retry the failed reconciliations."
	}
	components = append(components, reconciliation)

	if s.reports != nil {
		state, detail, guidance, link := s.reports.ReportHealth(probe)
		components = append(components, healthComponent{
			Name:     "Report sync",
			State:    state,
			Detail:   detail,
			Guidance: guidance,
			Link:     link,
		})
	}
	if s.hookwise != nil {
		state, detail, guidance, link := s.hookwise.Health(probe)
		components = append(components, healthComponent{
			Name: "Tickets", State: state, Detail: detail, Guidance: guidance, Link: link,
		})
	}

	return summarizeHealth(components)
}

func summarizeFeeds(feeds []gmp.Feed) healthComponent {
	component := healthComponent{Name: "Feeds", State: "ok", Link: "/settings"}
	syncing := 0
	var oldest time.Time
	for _, feed := range feeds {
		if feed.CurrentlySyncing {
			syncing++
		}
		if !feed.UpdatedAt.IsZero() && (oldest.IsZero() || feed.UpdatedAt.Before(oldest)) {
			oldest = feed.UpdatedAt
		}
	}
	switch {
	case syncing > 0:
		component.State = "degraded"
		component.Detail = "feed synchronization in progress"
	case !oldest.IsZero() && time.Since(oldest) > 8*24*time.Hour:
		component.State = "degraded"
		component.Detail = "feeds are older than 8 days"
		component.Guidance = "Check the Greenbone feed sync containers."
	default:
		component.Detail = "feeds current"
	}
	return component
}

func summarizeHealth(components []healthComponent) healthStrip {
	level := "green"
	summary := "All systems healthy"
	for _, component := range components {
		switch component.State {
		case "down":
			level = "red"
			summary = component.Name + " unavailable"
		case "degraded":
			if level != "red" {
				level = "amber"
				summary = component.Name + " degraded"
			}
		}
	}
	return healthStrip{
		Level:      level,
		Summary:    summary,
		CheckedAt:  time.Now(),
		Components: components,
	}
}
