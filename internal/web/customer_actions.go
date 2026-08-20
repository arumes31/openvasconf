package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"openvasconf/internal/customer"
	"openvasconf/internal/id"
	"openvasconf/internal/networkplan"
	"openvasconf/internal/store"
)

type selectiveSyncer interface {
	TriggerCustomers(customerIDs []string)
}

func (s *Server) triggerCustomers(customerIDs []string) {
	if syncer, ok := s.syncer.(selectiveSyncer); ok {
		syncer.TriggerCustomers(customerIDs)
		return
	}
	s.syncer.Trigger()
}

func (s *Server) customerSync(response http.ResponseWriter, request *http.Request) {
	value, err := s.repository.Customer(request.Context(), request.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || value.DeletedAt != nil {
		http.NotFound(response, request)
		return
	}
	if err != nil {
		s.internalError(response, err)
		return
	}
	s.triggerCustomers([]string{value.ID})
	http.Redirect(response, request, "/?notice=customer-sync-requested", http.StatusSeeOther)
}

func (s *Server) synchronizeSelected(response http.ResponseWriter, request *http.Request) {
	ids := request.PostForm["customer_id"]
	if len(ids) == 0 {
		http.Redirect(response, request, "/?notice=select-customers", http.StatusSeeOther)
		return
	}
	s.triggerCustomers(ids)
	http.Redirect(response, request, "/?notice=bulk-sync-requested", http.StatusSeeOther)
}

func (s *Server) customerHistory(response http.ResponseWriter, request *http.Request) {
	value, err := s.repository.Customer(request.Context(), request.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(response, request)
		return
	}
	if err != nil {
		s.internalError(response, err)
		return
	}
	runs, err := s.repository.ReconcileRuns(request.Context(), value.ID, 50)
	if err != nil {
		s.internalError(response, err)
		return
	}
	s.render(response, request, "history.html", pageData{
		Title:         "Reconciliation history",
		Authenticated: true,
		Form:          formFromCustomer(value),
		Runs:          runs,
	})
}

func (s *Server) customerClone(response http.ResponseWriter, request *http.Request) {
	source, err := s.repository.Customer(request.Context(), request.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || source.DeletedAt != nil {
		http.NotFound(response, request)
		return
	}
	if err != nil {
		s.internalError(response, err)
		return
	}
	settings, err := s.repository.Settings(request.Context())
	if err != nil {
		s.internalError(response, err)
		return
	}
	clone := source
	clone.ID, err = id.New()
	if err != nil {
		s.internalError(response, err)
		return
	}
	clone.Name = strings.TrimSpace(source.Name + " copy")
	clone.SafeName = networkplan.SafeName(clone.Name)
	clone.ScheduleWeekday, clone.ScheduleMinute, err = customer.RandomScheduleWithPolicy(nil, settings.SchedulePolicy)
	if err != nil {
		s.internalError(response, err)
		return
	}
	clone.Networks = make([]customer.Network, 0, len(source.Networks))
	for _, sourceNetwork := range source.Networks {
		networkID, newErr := id.New()
		if newErr != nil {
			s.internalError(response, newErr)
			return
		}
		clone.Networks = append(clone.Networks, customer.Network{
			ID: networkID, CustomerID: clone.ID, Input: sourceNetwork.Input,
			Prefix: sourceNetwork.Prefix, Class: sourceNetwork.Class,
		})
	}
	if err := s.repository.CreateCustomer(request.Context(), clone); err != nil {
		s.internalError(response, fmt.Errorf("cloning customer: %w", err))
		return
	}
	s.triggerCustomers([]string{clone.ID})
	http.Redirect(response, request, "/customers/"+clone.ID, http.StatusSeeOther)
}

func (s *Server) customerRandomize(response http.ResponseWriter, request *http.Request) {
	value, err := s.repository.Customer(request.Context(), request.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || value.DeletedAt != nil {
		http.NotFound(response, request)
		return
	}
	if err != nil {
		s.internalError(response, err)
		return
	}
	settings, err := s.repository.Settings(request.Context())
	if err != nil {
		s.internalError(response, err)
		return
	}
	value.ScheduleWeekday, value.ScheduleMinute, err = customer.RandomScheduleWithPolicy(nil, settings.SchedulePolicy)
	if err != nil {
		s.internalError(response, err)
		return
	}
	if err := s.repository.UpdateCustomer(request.Context(), value); err != nil {
		s.internalError(response, err)
		return
	}
	s.triggerCustomers([]string{value.ID})
	http.Redirect(response, request, "/customers/"+value.ID, http.StatusSeeOther)
}

func (s *Server) apiCustomerProgress(response http.ResponseWriter, request *http.Request) {
	value, err := s.repository.Customer(request.Context(), request.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(response, http.StatusNotFound, map[string]string{"error": "customer not found"})
		return
	}
	if err != nil {
		writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "progress unavailable"})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"status":     value.ReconciliationStatus,
		"safe_error": value.LastReconciliationError,
		"progress":   value.Reconciliation,
	})
}
