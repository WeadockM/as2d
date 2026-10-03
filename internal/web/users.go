package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/WeadockM/as2d/internal/accounts"
)

// accountsOnly answers for user endpoints when accounts are not set up yet.
func (s *site) accountsReady(w http.ResponseWriter) bool {
	if s.auth.accounts == nil {
		apiError(w, http.StatusNotFound, "user accounts are not configured; set password_pepper_file and state_dir")
		return false
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(v); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func (s *site) changePassword(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if p.User == nil {
		apiError(w, http.StatusBadRequest, "only signed-in users have a password to change")
		return
	}
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := s.auth.accounts.ChangePassword(*p.User, req.Current, req.New, p.session, remoteAddr(r)); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *site) listUsers(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	users, err := s.auth.accounts.Store.ListUsers()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, users)
}

// actor names who is acting, for the audit log.
func actor(r *http.Request) string {
	if p := principalOf(r); p.Name != "" {
		return p.Name
	}
	return "dashboard"
}

func (s *site) createUser(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	if !s.auth.accounts.Enabled() {
		apiError(w, http.StatusConflict, "create the first admin on the server with: as2d -create-admin <username>")
		return
	}
	var req struct {
		Username string        `json:"username"`
		Role     accounts.Role `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	temp, err := s.auth.accounts.CreateUser(actor(r), strings.TrimSpace(req.Username), req.Role, remoteAddr(r))
	switch {
	case errors.Is(err, accounts.ErrExists):
		apiError(w, http.StatusConflict, err.Error())
	case err != nil:
		apiError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSON(w, http.StatusCreated, map[string]any{"username": req.Username, "role": req.Role, "temporary_password": temp})
	}
}

func (s *site) updateUser(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	var req struct {
		Role     *accounts.Role `json:"role"`
		Disabled *bool          `json:"disabled"`
	}
	if !decode(w, r, &req) {
		return
	}
	name, by, addr := r.PathValue("username"), actor(r), remoteAddr(r)
	var err error
	if req.Role != nil {
		err = s.auth.accounts.SetRole(by, name, *req.Role, addr)
	}
	if err == nil && req.Disabled != nil {
		err = s.auth.accounts.SetDisabled(by, name, *req.Disabled, addr)
	}
	switch {
	case errors.Is(err, accounts.ErrNotFound):
		apiError(w, http.StatusNotFound, err.Error())
		return
	case err != nil:
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, _ := s.auth.accounts.Store.GetUser(name)
	writeJSON(w, http.StatusOK, u)
}

func (s *site) resetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	name := r.PathValue("username")
	if strings.EqualFold(name, principalOf(r).Name) {
		apiError(w, http.StatusBadRequest, "use Change password for your own account")
		return
	}
	temp, err := s.auth.accounts.ResetPassword(actor(r), name, remoteAddr(r))
	switch {
	case errors.Is(err, accounts.ErrNotFound):
		apiError(w, http.StatusNotFound, err.Error())
	case err != nil:
		apiError(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]any{"username": name, "temporary_password": temp})
	}
}

func (s *site) audit(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	q := r.URL.Query()
	f := accounts.AuditFilter{User: q.Get("user"), Action: q.Get("action")}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	entries, total, err := s.auth.accounts.Store.Audit(f)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "entries": entries})
}

// auditQueue records sends and retries made by signed-in users through the
// queue API. Scripts using the API token are not logged here; their sends
// are already in the message archive.
func (s *site) auditQueue(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principalOf(r)
		if r.Method != http.MethodPost || p.User == nil || s.auth.accounts == nil {
			h.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		if rec.status >= 400 {
			return
		}
		e := accounts.Entry{User: p.Name, Remote: remoteAddr(r)}
		if id, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/api/messages/"), "/retry"); ok {
			e.Action, e.Target = "message_retry", id
		} else {
			q := r.URL.Query()
			e.Action, e.Target = "message_send", q.Get("partner")
			e.Details = map[string]any{"filename": q.Get("filename")}
		}
		s.auth.accounts.Store.Record(e)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
