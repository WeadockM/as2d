package accounts

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go; no C compiler needed
)

// Role is what a user may do. Each role includes the ones below it.
type Role string

const (
	Viewer   Role = "viewer"   // see messages, the queue, partners and certificates
	Operator Role = "operator" // also retry failed messages and send files
	Admin    Role = "admin"    // also manage users and read the audit log
)

var roleRank = map[Role]int{Viewer: 1, Operator: 2, Admin: 3}

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return roleRank[r] > 0 }

// Allows reports whether r includes the permissions of min.
func (r Role) Allows(min Role) bool { return roleRank[r] >= roleRank[min] }

// User is a dashboard account.
type User struct {
	ID                 int64     `json:"-"`
	Username           string    `json:"username"`
	Role               Role      `json:"role"`
	Disabled           bool      `json:"disabled"`
	MustChangePassword bool      `json:"must_change_password"`
	Created            time.Time `json:"created"`
	LastLogin          time.Time `json:"last_login,omitzero"`

	hash, pepperID string
}

// Entry is one audit log record.
type Entry struct {
	ID      int64          `json:"id"`
	Time    time.Time      `json:"time"`
	User    string         `json:"user"` // username, or "cli" for command-line actions
	Action  string         `json:"action"`
	Target  string         `json:"target,omitempty"`
	Details map[string]any `json:"details,omitempty"`
	Remote  string         `json:"remote,omitempty"`
}

// Errors returned by the store and service.
var (
	ErrNotFound       = errors.New("no such user")
	ErrExists         = errors.New("a user with that name already exists")
	ErrBadCredentials = errors.New("wrong username or password")
	ErrLocked         = errors.New("too many failed sign-ins; try again later")
	ErrNoSession      = errors.New("not signed in")
)

// Store holds users, sessions and the audit log in SQLite. Unlike the
// message index, this data cannot be rebuilt, so the schema is migrated
// rather than reset.
type Store struct {
	db *sql.DB
}

var migrations = []string{
	// 1: users, sessions, audit log
	`CREATE TABLE users (
		id                   INTEGER PRIMARY KEY,
		username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
		role                 TEXT NOT NULL,
		password_hash        TEXT NOT NULL,
		pepper_id            TEXT NOT NULL,
		disabled             INTEGER NOT NULL DEFAULT 0,
		must_change_password INTEGER NOT NULL DEFAULT 0,
		created              INTEGER NOT NULL,
		last_login           INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE sessions (
		token_hash TEXT PRIMARY KEY, -- SHA-256 of the cookie value; the value itself is never stored
		user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
		created    INTEGER NOT NULL,
		expires    INTEGER NOT NULL,
		remote     TEXT NOT NULL
	);
	CREATE INDEX sessions_user ON sessions (user_id);
	CREATE TABLE audit (
		id      INTEGER PRIMARY KEY,
		time    INTEGER NOT NULL,
		user    TEXT NOT NULL,
		action  TEXT NOT NULL,
		target  TEXT NOT NULL,
		details TEXT NOT NULL,
		remote  TEXT NOT NULL
	);
	CREATE INDEX audit_time ON audit (time DESC);`,
}

// Open opens or creates the store at path, applying any new migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if version > len(migrations) {
		db.Close()
		return nil, fmt.Errorf("%s was written by a newer version of as2d (schema %d)", path, version)
	}
	for v := version; v < len(migrations); v++ {
		tx, err := db.Begin()
		if err == nil {
			if _, err = tx.Exec(migrations[v]); err == nil {
				if _, err = tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v+1)); err == nil {
					err = tx.Commit()
				}
			}
			if err != nil {
				tx.Rollback()
			}
		}
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: migrating to schema %d: %w", path, v+1, err)
		}
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// CheckUsername reports why a username is unacceptable, if it is.
func CheckUsername(name string) error {
	if !usernamePattern.MatchString(name) {
		return errors.New("usernames are 1 to 64 letters, digits and . _ @ -, starting with a letter or digit")
	}
	return nil
}

const userColumns = "id, username, role, password_hash, pepper_id, disabled, must_change_password, created, last_login"

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var created, last int64
	err := row.Scan(&u.ID, &u.Username, &u.Role, &u.hash, &u.pepperID, &u.Disabled, &u.MustChangePassword, &created, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	u.Created = time.Unix(created, 0).UTC()
	if last > 0 {
		u.LastLogin = time.Unix(last, 0).UTC()
	}
	return u, err
}

// CountUsers returns the number of users, disabled ones included.
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT count(*) FROM users").Scan(&n)
	return n, err
}

func (s *Store) createUser(username string, role Role, hash, pepperID string, mustChange bool) error {
	_, err := s.db.Exec(`INSERT INTO users (username, role, password_hash, pepper_id, must_change_password, created)
		VALUES (?, ?, ?, ?, ?, ?)`, username, role, hash, pepperID, mustChange, time.Now().Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrExists
	}
	return err
}

// GetUser looks a user up by name, ignoring case.
func (s *Store) GetUser(username string) (User, error) {
	return scanUser(s.db.QueryRow("SELECT "+userColumns+" FROM users WHERE username = ?", username))
}

// ListUsers returns all users by name.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query("SELECT " + userColumns + " FROM users ORDER BY username COLLATE NOCASE")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) exec(query string, args ...any) error {
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) setPassword(userID int64, hash, pepperID string, mustChange bool) error {
	return s.exec("UPDATE users SET password_hash = ?, pepper_id = ?, must_change_password = ? WHERE id = ?",
		hash, pepperID, mustChange, userID)
}

func (s *Store) setRole(userID int64, role Role) error {
	return s.exec("UPDATE users SET role = ? WHERE id = ?", role, userID)
}

func (s *Store) setDisabled(userID int64, disabled bool) error {
	return s.exec("UPDATE users SET disabled = ? WHERE id = ?", disabled, userID)
}

func (s *Store) touchLogin(userID int64) {
	s.db.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now().Unix(), userID)
}

// countActiveAdmins counts enabled admins.
func (s *Store) countActiveAdmins() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT count(*) FROM users WHERE role = ? AND disabled = 0", Admin).Scan(&n)
	return n, err
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) createSession(userID int64, ttl time.Duration, remote string) (string, error) {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	_, err := s.db.Exec("INSERT INTO sessions (token_hash, user_id, created, expires, remote) VALUES (?, ?, ?, ?, ?)",
		tokenHash(token), userID, now.Unix(), now.Add(ttl).Unix(), remote)
	return token, err
}

// sessionUser returns the user a session token belongs to, if the session
// is current and the user enabled.
func (s *Store) sessionUser(token string) (User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+prefixed("u.", userColumns)+` FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires > ? AND u.disabled = 0`, tokenHash(token), time.Now().Unix()))
	if errors.Is(err, ErrNotFound) {
		return User{}, ErrNoSession
	}
	return u, err
}

func prefixed(prefix, columns string) string {
	cols := strings.Split(columns, ", ")
	for i, c := range cols {
		cols[i] = prefix + c
	}
	return strings.Join(cols, ", ")
}

func (s *Store) deleteSession(token string) {
	s.db.Exec("DELETE FROM sessions WHERE token_hash = ?", tokenHash(token))
}

// deleteSessions ends a user's sessions, except keep if it is not empty.
func (s *Store) deleteSessions(userID int64, keep string) {
	s.db.Exec("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", userID, tokenHash(keep))
}

func (s *Store) purgeExpiredSessions() {
	s.db.Exec("DELETE FROM sessions WHERE expires <= ?", time.Now().Unix())
}

// Record adds an entry to the audit log.
func (s *Store) Record(e Entry) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	details := []byte("{}")
	if len(e.Details) > 0 {
		var err error
		if details, err = json.Marshal(e.Details); err != nil {
			return err
		}
	}
	_, err := s.db.Exec("INSERT INTO audit (time, user, action, target, details, remote) VALUES (?, ?, ?, ?, ?, ?)",
		e.Time.Unix(), e.User, e.Action, e.Target, string(details), e.Remote)
	return err
}

// AuditFilter selects audit entries. Zero fields match everything.
type AuditFilter struct {
	User   string
	Action string
	Limit  int // default 100, at most 500
	Offset int
}

// Audit returns matching entries, newest first, and the total number of
// matches.
func (s *Store) Audit(f AuditFilter) ([]Entry, int, error) {
	var where []string
	var args []any
	if f.User != "" {
		where = append(where, "user = ? COLLATE NOCASE")
		args = append(args, f.User)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := s.db.QueryRow("SELECT count(*) FROM audit"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	rows, err := s.db.Query("SELECT id, time, user, action, target, details, remote FROM audit"+cond+
		" ORDER BY id DESC LIMIT ? OFFSET ?", append(args, min(f.Limit, 500), max(f.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		var t int64
		var details string
		if err := rows.Scan(&e.ID, &t, &e.User, &e.Action, &e.Target, &details, &e.Remote); err != nil {
			return nil, 0, err
		}
		e.Time = time.Unix(t, 0).UTC()
		json.Unmarshal([]byte(details), &e.Details)
		out = append(out, e)
	}
	return out, total, rows.Err()
}
