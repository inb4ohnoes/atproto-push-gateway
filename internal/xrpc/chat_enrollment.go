package xrpc

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/dracoblue/atproto-push-gateway/internal/chat"
)

type ChatEnrollmentManager interface {
	Enroll(ctx context.Context, actorDID, appPassword, pdsHost string) error
	Revoke(actorDID string) error
	State(actorDID string) (string, error)
}

type enrollChatRequest struct {
	DID         string `json:"did"`
	AppPassword string `json:"appPassword"`
	PDSHost     string `json:"pdsHost"`
}

func (h *Handler) handleEnrollChat(w http.ResponseWriter, r *http.Request) {
	actorDID, err := h.verifyAuth(r, lexiconEnrollChat)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "auth_required", "invalid service auth")
		return
	}
	if h.chatEnrollment == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "not_configured", "DM push enrollment is unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var request enrollChatRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.DID == "" || request.AppPassword == "" || request.PDSHost == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "did, appPassword, and pdsHost are required")
		return
	}
	if request.DID != actorDID {
		writeJSONError(w, http.StatusForbidden, "actor_mismatch", "authenticated actor does not match did")
		return
	}
	err = h.chatEnrollment.Enroll(r.Context(), actorDID, request.AppPassword, request.PDSHost)
	switch {
	case errors.Is(err, chat.ErrBadPassword):
		writeJSONError(w, http.StatusUnauthorized, "invalid_app_password", "the app password was rejected")
	case errors.Is(err, chat.ErrDMAccess):
		writeJSONError(w, http.StatusForbidden, "dm_access_required", "recreate the app password with direct-message access enabled")
	case err != nil:
		log.Printf("[xrpc/chat-enrollment] enroll failed for %s: %v", actorDID, err)
		writeJSONError(w, http.StatusBadGateway, "enrollment_failed", "could not validate chat access")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"state": "active"})
	}
}

func (h *Handler) handleRevokeChat(w http.ResponseWriter, r *http.Request) {
	actorDID, err := h.verifyAuth(r, lexiconRevokeChat)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "auth_required", "invalid service auth")
		return
	}
	if h.chatEnrollment == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "not_configured", "DM push enrollment is unavailable")
		return
	}
	if err := h.chatEnrollment.Revoke(actorDID); err != nil {
		log.Printf("[xrpc/chat-enrollment] revoke failed for %s: %v", actorDID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "could not revoke enrollment")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleGetChatEnrollment(w http.ResponseWriter, r *http.Request) {
	actorDID, err := h.verifyAuth(r, lexiconGetChatEnrollment)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "auth_required", "invalid service auth")
		return
	}
	if h.chatEnrollment == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "not_configured", "DM push enrollment is unavailable")
		return
	}
	state, err := h.chatEnrollment.State(actorDID)
	if err != nil {
		log.Printf("[xrpc/chat-enrollment] status failed for %s: %v", actorDID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "could not read enrollment state")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": state})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}
