package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/WeadockM/as2d/internal/accounts"
)

// Sign-in works in one of three modes:
//
//   - users: once user accounts exist, people sign in with their own
//     username and password and get a server-side session. The API token
//     still works as a bearer token for scripts and Boomi, as an operator.
//   - token: before any accounts exist, the dashboard signs in with the API
//     token, using a stateless HMAC cookie, and has full access.
//   - open: with neither (only allowed on loopback), everything is open.
//
// Cookie-authenticated requests that change anything must carry the
// X-AS2D-Request header. A cross-site page can make the browser send the
// cookie, but cannot add that header, which stops CSRF.

const (
	tokenCookie   = "as2d_session" // token mode
	sessionCookie = "as2d_sid"     // users mode
	tokenSession  = 12 * time.Hour
	csrfHeader    = "X-AS2D-Request"
)

type auth struct {
	token    string
	secure   bool
	accounts *accounts.Service // nil when accounts are not configured
}

// principal is whoever is making a request.
type principal struct {
	Name        string // username, "api-token", or "" when open
	Role        accounts.Role
	User        *accounts.User // a signed-in user
	session     string         // the user's session token
	usedCookie  bool
	mustChange  bool
	description string // for messages: "signed-in user", "API token", ...
}

type ctxKey struct{}

func principalOf(r *http.Request) principal {
	p, _ := r.Context().Value(ctxKey{}).(principal)
	return p
}

func (a *auth) mode() string {
	switch {
	case a.accounts != nil && a.accounts.Enabled():
		return "users"
	case a.token != "":
		return "token"
	}
	return "open"
}

func (a *auth) mac(expiry string) string {
	m := hmac.New(sha256.New, []byte(a.token))
	m.Write([]byte("as2d-dashboard-session:" + expiry))
	return hex.EncodeToString(m.Sum(nil))
}

func (a *auth) validTokenCookie(r *http.Request) bool {
	c, err := r.Cookie(tokenCookie)
	if err != nil {
		return false
	}
	expiry, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	unix, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || time.Now().Unix() > unix {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(a.mac(expiry)))
}

func (a *auth) validBearer(r *http.Request) bool {
	return a.token != "" &&
		subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+a.token)) == 1
}

// authenticate identifies the caller, if it can.
func (a *auth) authenticate(r *http.Request) (principal, bool) {
	if a.validBearer(r) {
		return principal{Name: "api-token", Role: accounts.Operator, description: "the API token"}, true
	}
	switch a.mode() {
	case "users":
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			return principal{}, false
		}
		u, err := a.accounts.Session(c.Value)
		if err != nil {
			return principal{}, false
		}
		return principal{Name: u.Username, Role: u.Role, User: &u, session: c.Value, usedCookie: true,
			mustChange: u.MustChangePassword, description: "your role (" + string(u.Role) + ")"}, true
	case "token":
		if a.validTokenCookie(r) {
			return principal{Name: "api-token", Role: accounts.Admin, usedCookie: true}, true
		}
		return principal{}, false
	}
	return principal{Role: accounts.Admin}, true
}

// require lets a request through only for callers with at least role min.
func (a *auth) require(min accounts.Role, h http.Handler) http.Handler {
	return a.requireFunc(func(*http.Request) accounts.Role { return min }, h)
}

// requireFunc is require with the minimum role chosen per request.
func (a *auth) requireFunc(min func(*http.Request) accounts.Role, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := a.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			apiError(w, http.StatusUnauthorized, "sign in or send the API token")
			return
		}
		if p.usedCookie && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(csrfHeader) == "" {
			apiError(w, http.StatusForbidden, "missing "+csrfHeader+" header")
			return
		}
		if p.mustChange && r.URL.Path != "/api/account/password" {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "choose a new password before continuing", "code": "password_change_required"})
			return
		}
		if need := min(r); !p.Role.Allows(need) {
			who := p.description
			if who == "" {
				who = "this sign-in"
			}
			apiError(w, http.StatusForbidden, who+" does not allow this; it needs "+string(need))
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *site) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.auth.secure, SameSite: http.SameSiteStrictMode,
	})
}

func (s *site) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req)
	addr := remoteAddr(r)

	switch s.auth.mode() {
	case "users":
		token, u, err := s.auth.accounts.Login(strings.TrimSpace(req.Username), req.Password, addr)
		switch {
		case errors.Is(err, accounts.ErrLocked):
			apiError(w, http.StatusTooManyRequests, err.Error())
			return
		case errors.Is(err, accounts.ErrBadCredentials):
			time.Sleep(300 * time.Millisecond)
			apiError(w, http.StatusUnauthorized, err.Error())
			return
		case err != nil:
			s.cfg.Log.Error("sign-in failed", "err", err)
			apiError(w, http.StatusInternalServerError, "sign-in failed")
			return
		}
		s.setCookie(w, sessionCookie, token, int(accounts.SessionLength.Seconds()))
		s.cfg.Log.Info("dashboard sign-in", "user", u.Username, "remote", addr)
		w.WriteHeader(http.StatusNoContent)

	case "token":
		if subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.auth.token)) != 1 {
			time.Sleep(500 * time.Millisecond) // slow down guessing
			s.cfg.Log.Warn("dashboard sign-in failed", "remote", addr)
			apiError(w, http.StatusUnauthorized, "wrong token")
			return
		}
		expiry := strconv.FormatInt(time.Now().Add(tokenSession).Unix(), 10)
		s.setCookie(w, tokenCookie, expiry+"."+s.auth.mac(expiry), int(tokenSession.Seconds()))
		s.cfg.Log.Info("dashboard sign-in with the API token", "remote", addr)
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *site) logout(w http.ResponseWriter, r *http.Request) {
	if p, ok := s.auth.authenticate(r); ok && p.User != nil {
		s.auth.accounts.Logout(p.session, *p.User, remoteAddr(r))
	}
	s.setCookie(w, sessionCookie, "", -1)
	s.setCookie(w, tokenCookie, "", -1)
	w.WriteHeader(http.StatusNoContent)
}
