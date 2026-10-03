package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The dashboard logs in with the API token. A successful login sets a
// session cookie holding an expiry time and an HMAC of it keyed by the
// token, so no server-side session state is needed and changing the token
// logs everyone out. Scripts can keep using "Authorization: Bearer".
//
// Cookie-authenticated requests that change anything must carry the
// X-AS2D-Request header. A cross-site page can make the browser send the
// cookie, but cannot add that header, which stops CSRF.

const (
	cookieName    = "as2d_session"
	sessionLength = 12 * time.Hour
	csrfHeader    = "X-AS2D-Request"
)

type auth struct {
	token  string
	secure bool
}

func newAuth(token string, secure bool) *auth { return &auth{token: token, secure: secure} }

func (a *auth) mac(expiry string) string {
	m := hmac.New(sha256.New, []byte(a.token))
	m.Write([]byte("as2d-dashboard-session:" + expiry))
	return hex.EncodeToString(m.Sum(nil))
}

func (a *auth) validCookie(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
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
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+a.token)) == 1
}

// ok reports whether the request is authenticated.
func (a *auth) ok(r *http.Request) bool {
	return a.token == "" || a.validBearer(r) || a.validCookie(r)
}

func (a *auth) require(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case a.token == "" || a.validBearer(r):
		case a.validCookie(r):
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(csrfHeader) == "" {
				apiError(w, http.StatusForbidden, "missing "+csrfHeader+" header")
				return
			}
		default:
			w.Header().Set("WWW-Authenticate", "Bearer")
			apiError(w, http.StatusUnauthorized, "log in or send the API token")
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *site) login(w http.ResponseWriter, r *http.Request) {
	a := s.auth
	if a.token == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(a.token)) != 1 {
		time.Sleep(500 * time.Millisecond) // slow down guessing
		s.cfg.Log.Warn("dashboard login failed", "remote", r.RemoteAddr)
		apiError(w, http.StatusUnauthorized, errBadLogin.Error())
		return
	}
	expiry := strconv.FormatInt(time.Now().Add(sessionLength).Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: expiry + "." + a.mac(expiry), Path: "/",
		MaxAge: int(sessionLength.Seconds()), HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode,
	})
	s.cfg.Log.Info("dashboard login", "remote", r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}

func (s *site) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: s.auth.secure, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}
