package web

import (
	"errors"
	"net/http"
	"strconv"

	"openvasconf/internal/store"
)

func (s *Server) scanAlertAcknowledge(response http.ResponseWriter, request *http.Request) {
	alertID, err := strconv.ParseInt(request.PathValue("id"), 10, 64)
	if err != nil || alertID < 1 {
		http.NotFound(response, request)
		return
	}
	if err := s.repository.AcknowledgeScanAlert(request.Context(), alertID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(response, request)
			return
		}
		s.internalError(response, err)
		return
	}
	http.Redirect(response, request, "/?notice=scan-alert-acknowledged", http.StatusSeeOther)
}
