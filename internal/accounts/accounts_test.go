package accounts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func peppers(t *testing.T, secrets ...string) *Peppers {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for i, s := range secrets {
		p := filepath.Join(dir, string(rune('a'+i))+".key")
		os.WriteFile(p, []byte(s+"\n"), 0o600)
		paths = append(paths, p)
	}
	ps, err := LoadPeppers(paths[0], paths[1:])
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

var pepperA, pepperB = strings.Repeat("a", 64), strings.Repeat("b", 64)

func TestHashAndPepper(t *testing.T) {
	ps := peppers(t, pepperA)
	hash, id := ps.Hash("correct horse battery")
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=2,p=2$") || id != ps.Current.ID {
		t.Fatalf("hash %q id %q", hash, id)
	}
	if ok, rehash := ps.Verify(hash, id, "correct horse battery"); !ok || rehash {
		t.Errorf("right password: ok=%v rehash=%v", ok, rehash)
	}
	if ok, _ := ps.Verify(hash, id, "correct horse batterY"); ok {
		t.Error("wrong password accepted")
	}
	// The same hash is useless without the pepper that made it.
	other := peppers(t, pepperB)
	if ok, _ := other.Verify(hash, other.Current.ID, "correct horse battery"); ok {
		t.Error("hash verified with a different pepper")
	}
}

func TestPepperRotation(t *testing.T) {
	old := peppers(t, pepperA)
	hash, id := old.Hash("correct horse battery")

	rotated := peppers(t, pepperB, pepperA) // B is current, A still known
	ok, rehash := rotated.Verify(hash, id, "correct horse battery")
	if !ok || !rehash {
		t.Fatalf("old-pepper hash: ok=%v rehash=%v", ok, rehash)
	}
	if peppers(t, pepperB).byID[id].key != nil {
		t.Error("dropped pepper still known")
	}
}

func TestLoadPepperRejectsShortSecrets(t *testing.T) {
	p := filepath.Join(t.TempDir(), "p.key")
	os.WriteFile(p, []byte("short"), 0o600)
	if _, err := LoadPeppers(p, nil); err == nil {
		t.Error("short pepper accepted")
	}
}

func TestPasswordRules(t *testing.T) {
	for pw, ok := range map[string]bool{
		"short":                          false,
		"exactly12chr":                   true,
		"mason.weadock":                  false, // the username
		strings.Repeat("x", 257):         false,
		"a long passphrase with spaces ": true,
	} {
		if err := CheckPassword("Mason.Weadock", pw); (err == nil) != ok {
			t.Errorf("%q: err = %v", pw, err)
		}
	}
	if p := GeneratePassword(); len(p) != 24 || CheckPassword("x", p) != nil {
		t.Errorf("generated %q", p)
	}
}

func newService(t *testing.T) *Service {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return NewService(st, peppers(t, pepperA))
}

func TestLoginLifecycle(t *testing.T) {
	s := newService(t)
	if s.Enabled() {
		t.Fatal("enabled with no users")
	}
	temp, err := s.CreateUser("cli", "mason", Admin, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("cli", "MASON", Viewer, ""); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate (case-insensitive) user: %v", err)
	}

	token, u, err := s.Login("Mason", temp, "10.0.0.1")
	if err != nil || !u.MustChangePassword || u.Role != Admin {
		t.Fatalf("login with one-time password: %+v, %v", u, err)
	}
	if err := s.ChangePassword(u, temp, "a much better password", token, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	u, err = s.Session(token)
	if err != nil || u.MustChangePassword {
		t.Fatalf("session after password change: %+v, %v", u, err)
	}
	if _, _, err := s.Login("mason", temp, "10.0.0.1"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("old one-time password still works: %v", err)
	}

	s.Logout(token, u, "10.0.0.1")
	if _, err := s.Session(token); !errors.Is(err, ErrNoSession) {
		t.Errorf("session after logout: %v", err)
	}

	entries, _, _ := s.Store.Audit(AuditFilter{User: "mason"})
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	if got := strings.Join(actions, ","); got != "logout,login_failed,password_change,login" {
		t.Errorf("audit trail = %s", got)
	}
}

func TestLockout(t *testing.T) {
	s := newService(t)
	temp, _ := s.CreateUser("cli", "op", Operator, "")
	for range maxFailures {
		if _, _, err := s.Login("op", "wrong password!", "10.0.0.2"); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("wrong password: %v", err)
		}
	}
	if _, _, err := s.Login("op", temp, "10.0.0.2"); !errors.Is(err, ErrLocked) {
		t.Errorf("right password while locked: %v", err)
	}
	// Unknown users are throttled the same way, without revealing they don't exist.
	for range maxFailures {
		s.Login("ghost", "whatever-password", "10.0.0.3")
	}
	if _, _, err := s.Login("ghost", "whatever-password", "10.0.0.3"); !errors.Is(err, ErrLocked) {
		t.Errorf("unknown user not throttled: %v", err)
	}
}

func TestAdminSafeguards(t *testing.T) {
	s := newService(t)
	s.CreateUser("cli", "alice", Admin, "")
	opTemp, _ := s.CreateUser("alice", "bob", Operator, "")

	if err := s.SetRole("alice", "alice", Viewer, ""); err == nil {
		t.Error("admin changed own role")
	}
	if err := s.SetDisabled("alice", "alice", true, ""); err == nil {
		t.Error("admin disabled self")
	}
	// bob is signed in; disabling him ends his session at once.
	token, _, err := s.Login("bob", opTemp, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled("alice", "bob", true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(token); !errors.Is(err, ErrNoSession) {
		t.Errorf("disabled user's session still valid: %v", err)
	}
	if _, _, err := s.Login("bob", opTemp, ""); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("disabled user signed in: %v", err)
	}

	// The last active admin cannot be demoted or disabled by another admin.
	s.SetDisabled("alice", "bob", false, "")
	s.SetRole("alice", "bob", Admin, "")
	if err := s.SetRole("bob", "alice", Viewer, ""); err != nil {
		t.Fatalf("demoting one of two admins: %v", err)
	}
	if err := s.SetDisabled("alice", "bob", true, ""); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disabling the last admin: %v", err)
	}

	// A password reset ends sessions and forces a change.
	bobToken, _, _ := s.Login("bob", opTemp, "")
	temp, err := s.ResetPassword("alice", "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(bobToken); !errors.Is(err, ErrNoSession) {
		t.Error("session survived a password reset")
	}
	if _, u, err := s.Login("bob", temp, ""); err != nil || !u.MustChangePassword {
		t.Errorf("after reset: %+v, %v", u, err)
	}
}

func TestStoreReopenKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	st, _ := Open(path)
	s := NewService(st, peppers(t, pepperA))
	s.CreateUser("cli", "keep", Viewer, "")
	st.Close()

	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if n, _ := st2.CountUsers(); n != 1 {
		t.Errorf("users after reopening: %d", n)
	}
}
