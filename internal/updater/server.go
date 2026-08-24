package updater

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const maxRequestBytes = 32 << 10

type Handler struct {
	manager Manager
}

func NewHandler(manager Manager) (*Handler, error) {
	if manager == nil {
		return nil, errors.New("updater: manager is required")
	}
	return &Handler{manager: manager}, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Security-Policy", "default-src 'none'")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Frame-Options", "DENY")
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/v1/status":
		h.status(response, request)
	case request.Method == http.MethodPut && request.URL.Path == "/v1/policy":
		h.configure(response, request)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/operations/check":
		h.trigger(response, request, KindCheck)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/operations/feed":
		h.trigger(response, request, KindFeed)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/operations/stack":
		h.trigger(response, request, KindStack)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/acknowledge":
		h.acknowledge(response, request)
	default:
		writeHelperJSON(response, http.StatusNotFound, ErrorResponse{Error: "not found"})
	}
}

func (h *Handler) status(response http.ResponseWriter, request *http.Request) {
	status, err := h.manager.Status(request.Context())
	if err != nil {
		writeHelperJSON(response, http.StatusServiceUnavailable, ErrorResponse{Error: "status unavailable"})
		return
	}
	writeHelperJSON(response, http.StatusOK, status)
}

func (h *Handler) configure(response http.ResponseWriter, request *http.Request) {
	var policy Policy
	if err := decodeHelperJSON(response, request, &policy); err != nil {
		writeHelperJSON(response, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	if err := h.manager.Configure(request.Context(), policy); err != nil {
		writeHelperJSON(response, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	writeHelperJSON(response, http.StatusNoContent, nil)
}

func (h *Handler) trigger(response http.ResponseWriter, request *http.Request, kind Kind) {
	var trigger TriggerRequest
	if err := decodeHelperJSON(response, request, &trigger); err != nil {
		writeHelperJSON(response, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	operation, err := h.manager.Trigger(request.Context(), kind, trigger)
	if err != nil {
		switch {
		case errors.Is(err, ErrBusy):
			writeHelperJSON(response, http.StatusConflict, ErrorResponse{Error: "another update is active"})
		case errors.Is(err, ErrPaused):
			writeHelperJSON(response, http.StatusLocked, ErrorResponse{Error: "automatic stack updates are paused"})
		default:
			writeHelperJSON(response, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		}
		return
	}
	writeHelperJSON(response, http.StatusAccepted, operation)
}

func (h *Handler) acknowledge(response http.ResponseWriter, request *http.Request) {
	var empty struct{}
	if err := decodeHelperJSON(response, request, &empty); err != nil {
		writeHelperJSON(response, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	if err := h.manager.Acknowledge(request.Context()); err != nil {
		writeHelperJSON(response, http.StatusServiceUnavailable, ErrorResponse{Error: "acknowledgement failed"})
		return
	}
	writeHelperJSON(response, http.StatusNoContent, nil)
}

func decodeHelperJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid request body")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func writeHelperJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(response).Encode(value)
	}
}
