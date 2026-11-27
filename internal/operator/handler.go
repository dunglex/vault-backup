package operator

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
)

type Dependencies struct {
	RequireAdmin   func(http.ResponseWriter, *http.Request) bool
	Audit          func(*http.Request, string, string, string, string, string, string)
	Actor          func(*http.Request, string) string
	AccountExists  func(string) (bool, error)
	RevokeTokens   func(string) error
	RevokeSessions func(string)
	ValidPath      func(string) bool
	ValidMount     func(string) bool
	MountExists    func(string) (bool, error)
}

type Handler struct {
	db   *sql.DB
	deps Dependencies
}

func NewHandler(db *sql.DB, deps Dependencies) *Handler {
	return &Handler{db: db, deps: deps}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	return h.deps.RequireAdmin != nil && h.deps.RequireAdmin(w, r)
}

func (h *Handler) audit(r *http.Request, action, outcome, actor, source, resource, detail string) {
	if h.deps.Audit != nil {
		h.deps.Audit(r, action, outcome, actor, source, resource, detail)
	}
}

func (h *Handler) actor(r *http.Request, source string) string {
	if h.deps.Actor == nil {
		return "unknown"
	}
	return h.deps.Actor(r, source)
}

func (h *Handler) normalizeSecretMounts(mounts []string) ([]string, error) {
	if h.deps.ValidMount == nil {
		return nil, fmt.Errorf("secret mount validation is unavailable")
	}
	return NormalizeSecretMounts(mounts, h.deps.ValidMount)
}

func (h *Handler) decodeSecretMounts(encoded string) ([]string, error) {
	if h.deps.ValidMount == nil {
		return nil, fmt.Errorf("secret mount validation is unavailable")
	}
	return DecodeSecretMounts(encoded, h.deps.ValidMount)
}

func (h *Handler) requireActiveMounts(mounts []string) error {
	if h.deps.MountExists == nil {
		return fmt.Errorf("secret mount lookup is unavailable")
	}
	for _, mount := range mounts {
		exists, err := h.deps.MountExists(mount)
		if err != nil {
			return fmt.Errorf("could not verify secret mount")
		}
		if !exists {
			return fmt.Errorf("mount %q does not exist or is deleted", mount)
		}
	}
	return nil
}
