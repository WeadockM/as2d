package accounts

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// SessionLength is how long a sign-in lasts.
const SessionLength = 12 * time.Hour

// Sign-in throttling: after maxFailures failed attempts for one username,
// or maxFailures*4 from one address, within lockWindow, further attempts
// are refused until the window has passed.
const (
	maxFailures = 5
	lockWindow  = 15 * time.Minute
)

// Service is the accounts API used by the dashboard and the command line.
type Service struct {
	Store   *Store
	Peppers *Peppers

	mu       sync.Mutex
	failures map[string][]time.Time // by "user:<name>" and "addr:<ip>"
}

func NewService(store *Store, peppers *Peppers) *Service {
	return &Service{Store: store, Peppers: peppers, failures: map[string][]time.Time{}}
}

// Enabled reports whether users have been set up. Until then the dashboard
// falls back to signing in with the API token.
func (s *Service) Enabled() bool {
	n, err := s.Store.CountUsers()
	return err == nil && n > 0
}

func (s *Service) recentFailures(key string, now time.Time) []time.Time {
	recent := s.failures[key][:0]
	for _, t := range s.failures[key] {
		if now.Sub(t) < lockWindow {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(s.failures, key)
		return nil
	}
	s.failures[key] = recent
	return recent
}

func (s *Service) locked(username, addr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	return len(s.recentFailures("user:"+strings.ToLower(username), now)) >= maxFailures ||
		len(s.recentFailures("addr:"+addr, now)) >= maxFailures*4
}

func (s *Service) fail(username, addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, key := range []string{"user:" + strings.ToLower(username), "addr:" + addr} {
		s.failures[key] = append(s.failures[key], now)
	}
}

// Login checks a username and password and starts a session. It returns
// the session token for the cookie. Every outcome is recorded in the audit
// log.
func (s *Service) Login(username, password, addr string) (string, User, error) {
	audit := func(action string, details map[string]any) {
		s.Store.Record(Entry{User: username, Action: action, Remote: addr, Details: details})
	}
	if s.locked(username, addr) {
		audit("login_refused", map[string]any{"reason": "too many failed attempts"})
		return "", User{}, ErrLocked
	}
	u, err := s.Store.GetUser(username)
	if errors.Is(err, ErrNotFound) {
		s.Peppers.burn(password) // take as long as a real check
		s.fail(username, addr)
		audit("login_failed", map[string]any{"reason": "unknown user"})
		return "", User{}, ErrBadCredentials
	}
	if err != nil {
		return "", User{}, err
	}
	ok, rehash := s.Peppers.Verify(u.hash, u.pepperID, password)
	if !ok {
		s.fail(username, addr)
		audit("login_failed", map[string]any{"reason": "wrong password"})
		return "", User{}, ErrBadCredentials
	}
	if u.Disabled {
		audit("login_failed", map[string]any{"reason": "account disabled"})
		return "", User{}, ErrBadCredentials
	}
	if rehash {
		hash, pepperID := s.Peppers.Hash(password)
		s.Store.setPassword(u.ID, hash, pepperID, u.MustChangePassword)
	}
	token, err := s.Store.createSession(u.ID, SessionLength, addr)
	if err != nil {
		return "", User{}, err
	}
	s.Store.touchLogin(u.ID)
	s.Store.purgeExpiredSessions()
	s.Store.Record(Entry{User: u.Username, Action: "login", Remote: addr})
	return token, u, nil
}

// Session returns the user a session token belongs to.
func (s *Service) Session(token string) (User, error) {
	if token == "" {
		return User{}, ErrNoSession
	}
	return s.Store.sessionUser(token)
}

// Logout ends a session.
func (s *Service) Logout(token string, u User, addr string) {
	s.Store.deleteSession(token)
	s.Store.Record(Entry{User: u.Username, Action: "logout", Remote: addr})
}

// ChangePassword sets a user's own password after checking the current
// one. Their other sessions are ended; keepToken stays signed in.
func (s *Service) ChangePassword(u User, current, next, keepToken, addr string) error {
	fresh, err := s.Store.GetUser(u.Username)
	if err != nil {
		return err
	}
	if ok, _ := s.Peppers.Verify(fresh.hash, fresh.pepperID, current); !ok {
		s.Store.Record(Entry{User: u.Username, Action: "password_change_failed", Remote: addr,
			Details: map[string]any{"reason": "wrong current password"}})
		return errors.New("the current password is wrong")
	}
	if current == next {
		return errors.New("choose a password different from the current one")
	}
	if err := CheckPassword(u.Username, next); err != nil {
		return err
	}
	hash, pepperID := s.Peppers.Hash(next)
	if err := s.Store.setPassword(fresh.ID, hash, pepperID, false); err != nil {
		return err
	}
	s.Store.deleteSessions(fresh.ID, keepToken)
	return s.Store.Record(Entry{User: u.Username, Action: "password_change", Remote: addr})
}

// CreateUser adds a user with a one-time password, which is returned and
// must be changed at first sign-in.
func (s *Service) CreateUser(actor, username string, role Role, addr string) (string, error) {
	if err := CheckUsername(username); err != nil {
		return "", err
	}
	if !role.Valid() {
		return "", errors.New("role must be viewer, operator or admin")
	}
	temp := GeneratePassword()
	hash, pepperID := s.Peppers.Hash(temp)
	if err := s.Store.createUser(username, role, hash, pepperID, true); err != nil {
		return "", err
	}
	s.Store.Record(Entry{User: actor, Action: "user_create", Target: username, Remote: addr,
		Details: map[string]any{"role": role}})
	return temp, nil
}

// ResetPassword gives a user a new one-time password and ends their
// sessions.
func (s *Service) ResetPassword(actor, username, addr string) (string, error) {
	u, err := s.Store.GetUser(username)
	if err != nil {
		return "", err
	}
	temp := GeneratePassword()
	hash, pepperID := s.Peppers.Hash(temp)
	if err := s.Store.setPassword(u.ID, hash, pepperID, true); err != nil {
		return "", err
	}
	s.Store.deleteSessions(u.ID, "")
	s.Store.Record(Entry{User: actor, Action: "user_password_reset", Target: u.Username, Remote: addr})
	return temp, nil
}

// ErrLastAdmin protects against locking everyone out.
var ErrLastAdmin = errors.New("this is the only active admin; make another user an admin first")

// SetRole changes a user's role. Admins cannot change their own role.
func (s *Service) SetRole(actor, username string, role Role, addr string) error {
	if !role.Valid() {
		return errors.New("role must be viewer, operator or admin")
	}
	u, err := s.Store.GetUser(username)
	if err != nil {
		return err
	}
	if strings.EqualFold(actor, u.Username) {
		return errors.New("you cannot change your own role")
	}
	if u.Role == role {
		return nil
	}
	if u.Role == Admin && !u.Disabled {
		if n, err := s.Store.countActiveAdmins(); err != nil || n <= 1 {
			return ErrLastAdmin
		}
	}
	if err := s.Store.setRole(u.ID, role); err != nil {
		return err
	}
	return s.Store.Record(Entry{User: actor, Action: "user_role", Target: u.Username, Remote: addr,
		Details: map[string]any{"from": u.Role, "to": role}})
}

// SetDisabled disables or re-enables a user. Disabling ends their sessions
// at once. Admins cannot disable themselves.
func (s *Service) SetDisabled(actor, username string, disabled bool, addr string) error {
	u, err := s.Store.GetUser(username)
	if err != nil {
		return err
	}
	if strings.EqualFold(actor, u.Username) {
		return errors.New("you cannot disable your own account")
	}
	if u.Disabled == disabled {
		return nil
	}
	if disabled && u.Role == Admin {
		if n, err := s.Store.countActiveAdmins(); err != nil || n <= 1 {
			return ErrLastAdmin
		}
	}
	if err := s.Store.setDisabled(u.ID, disabled); err != nil {
		return err
	}
	action := "user_enable"
	if disabled {
		action = "user_disable"
		s.Store.deleteSessions(u.ID, "")
	}
	return s.Store.Record(Entry{User: actor, Action: action, Target: u.Username, Remote: addr})
}
