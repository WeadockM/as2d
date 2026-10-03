package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/WeadockM/as2d/internal/accounts"
	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/index"
	"github.com/WeadockM/as2d/internal/outbound"
)

type usersSite struct {
	*httptest.Server
	svc   *accounts.Service
	temps map[string]string // one-time passwords by username
}

func newUsersSite(t *testing.T) *usersSite {
	t.Helper()
	dir := t.TempDir()
	pepper := filepath.Join(dir, "pepper.key")
	os.WriteFile(pepper, []byte(accounts.GeneratePepper()), 0o600)
	peppers, err := accounts.LoadPeppers(pepper, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := accounts.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := accounts.NewService(st, peppers)

	db, _, _ := index.Open(filepath.Join(dir, "as2d.db"), dir)
	t.Cleanup(func() { db.Close() })
	mgr, err := outbound.New(outbound.Config{
		SpoolDir: filepath.Join(dir, "spool"), Archive: &archive.Store{Root: dir}, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}

	temps := map[string]string{}
	for name, role := range map[string]accounts.Role{"alice": accounts.Admin, "otto": accounts.Operator, "vic": accounts.Viewer} {
		if temps[name], err = svc.CreateUser("cli", name, role, ""); err != nil {
			t.Fatal(err)
		}
	}
	h := Handler(Config{
		Index: db, Queue: mgr, Accounts: svc, Token: "api-secret",
		Local: as2.Station{ID: "US", Cert: cert(t, "US", time.Now().AddDate(1, 0, 0))},
		Log:   slog.New(slog.DiscardHandler),
	})
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return &usersSite{s, svc, temps}
}

// client is a browser session: it keeps cookies and sends the CSRF header.
type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func (s *usersSite) client(t *testing.T) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t, s.URL, &http.Client{Jar: jar}}
}

func (c *client) do(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeader, "1")
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func (c *client) login(user, password string) int {
	c.t.Helper()
	code, _ := c.do("POST", "/api/login", `{"username":"`+user+`","password":"`+password+`"}`)
	return code
}

// signIn signs in with the one-time password and sets a real one.
func (s *usersSite) signIn(t *testing.T, user string) *client {
	t.Helper()
	c := s.client(t)
	if code := c.login(user, s.temps[user]); code != http.StatusNoContent {
		t.Fatalf("login %s: %d", user, code)
	}
	if code, body := c.do("POST", "/api/account/password",
		`{"current_password":"`+s.temps[user]+`","new_password":"`+user+` has a long password"}`); code != http.StatusNoContent {
		t.Fatalf("password change for %s: %d %v", user, code, body)
	}
	return c
}

func TestFirstLoginMustChangePassword(t *testing.T) {
	s := newUsersSite(t)
	c := s.client(t)
	if code := c.login("alice", s.temps["alice"]); code != http.StatusNoContent {
		t.Fatalf("login: %d", code)
	}
	_, sess := c.do("GET", "/api/session", "")
	user, _ := sess["user"].(map[string]any)
	if sess["auth_mode"] != "users" || user["must_change_password"] != true || user["role"] != "admin" {
		t.Fatalf("session = %v", sess)
	}
	if code, body := c.do("GET", "/api/archive/messages", ""); code != http.StatusForbidden || body["code"] != "password_change_required" {
		t.Errorf("before changing password: %d %v", code, body)
	}
	if code, _ := c.do("POST", "/api/account/password", `{"current_password":"`+s.temps["alice"]+`","new_password":"short"}`); code != http.StatusBadRequest {
		t.Errorf("short new password: %d", code)
	}
	if code, _ := c.do("POST", "/api/account/password", `{"current_password":"`+s.temps["alice"]+`","new_password":"a properly long password"}`); code != http.StatusNoContent {
		t.Fatalf("password change: %d", code)
	}
	if code, _ := c.do("GET", "/api/archive/messages", ""); code != http.StatusOK {
		t.Errorf("after changing password: %d", code)
	}
}

func TestRolesAreEnforced(t *testing.T) {
	s := newUsersSite(t)
	viewer, operator, admin := s.signIn(t, "vic"), s.signIn(t, "otto"), s.signIn(t, "alice")

	for _, tc := range []struct {
		c            *client
		method, path string
		want         int
	}{
		{viewer, "GET", "/api/archive/messages", 200},
		{viewer, "GET", "/api/messages", 200},
		{viewer, "POST", "/api/messages/nope/retry", 403},
		{operator, "POST", "/api/messages/nope/retry", 409}, // allowed; the job doesn't exist
		{operator, "GET", "/api/users", 403},
		{operator, "GET", "/api/audit", 403},
		{admin, "GET", "/api/users", 200},
		{admin, "GET", "/api/audit", 200},
	} {
		if code, body := tc.c.do(tc.method, tc.path, ""); code != tc.want {
			t.Errorf("%s %s: %d, want %d (%v)", tc.method, tc.path, code, tc.want, body)
		}
	}

	// The API token keeps working for scripts, as an operator.
	req, _ := http.NewRequest("GET", s.URL+"/api/users", nil)
	req.Header.Set("Authorization", "Bearer api-secret")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusForbidden {
		t.Errorf("token reading users: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", s.URL+"/api/messages", nil)
	req.Header.Set("Authorization", "Bearer api-secret")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusOK {
		t.Errorf("token reading the queue: %d", resp.StatusCode)
	}
	// But it no longer signs in to the dashboard.
	if code, _ := s.client(t).do("POST", "/api/login", `{"token":"api-secret"}`); code != http.StatusUnauthorized {
		t.Errorf("token sign-in once users exist: %d", code)
	}
}

func TestUserManagementAndAudit(t *testing.T) {
	s := newUsersSite(t)
	admin := s.signIn(t, "alice")

	code, body := admin.do("POST", "/api/users", `{"username":"dana","role":"operator"}`)
	temp, _ := body["temporary_password"].(string)
	if code != http.StatusCreated || len(temp) != 24 {
		t.Fatalf("create user: %d %v", code, body)
	}
	if code, _ := admin.do("POST", "/api/users", `{"username":"Dana","role":"viewer"}`); code != http.StatusConflict {
		t.Errorf("duplicate user: %d", code)
	}
	if code, _ := admin.do("POST", "/api/users", `{"username":"eve","role":"superuser"}`); code != http.StatusBadRequest {
		t.Errorf("bad role: %d", code)
	}

	dana := s.client(t)
	if code := dana.login("dana", temp); code != http.StatusNoContent {
		t.Fatalf("new user sign-in: %d", code)
	}
	if code, _ := admin.do("PATCH", "/api/users/dana", `{"disabled":true}`); code != http.StatusOK {
		t.Fatalf("disable: %d", code)
	}
	if code, _ := dana.do("GET", "/api/session", ""); code != 200 {
		t.Fatal("session endpoint")
	}
	if code, _ := dana.do("POST", "/api/account/password", `{}`); code != http.StatusUnauthorized {
		t.Errorf("disabled user's session still works: %d", code)
	}
	if code, _ := admin.do("PATCH", "/api/users/alice", `{"disabled":true}`); code != http.StatusBadRequest {
		t.Errorf("admin disabling self: %d", code)
	}

	// Wrong passwords are refused, then throttled.
	stranger := s.client(t)
	for range 5 {
		if code := stranger.login("vic", "not the password"); code != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", code)
		}
	}
	if code := stranger.login("vic", s.temps["vic"]); code != http.StatusTooManyRequests {
		t.Errorf("after 5 failures: %d", code)
	}

	_, audit := admin.do("GET", "/api/audit?limit=50", "")
	var actions []string
	for _, e := range audit["entries"].([]any) {
		actions = append(actions, e.(map[string]any)["action"].(string))
	}
	joined := strings.Join(actions, ",")
	for _, want := range []string{"user_create", "user_disable", "login", "password_change", "login_failed", "login_refused"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit log lacks %s: %s", want, joined)
		}
	}
}
