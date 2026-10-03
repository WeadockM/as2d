// Package accounts manages dashboard users: password hashing, sessions,
// roles and the audit log.
//
// Passwords are hashed with Argon2id after being combined with a secret
// pepper (HMAC-SHA256). The pepper lives in a file outside the database, so
// a copy of the database alone is not enough to attack the passwords. Each
// hash records which pepper it used, so the pepper can be rotated: users
// are moved to the new one as they next sign in.
package accounts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for new hashes (OWASP's recommendations allow less;
// these suit a server handling a few sign-ins a minute).
const (
	argonTime    = 2
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// hashing limits concurrent Argon2id computations, each of which uses
// argonMemory, so a burst of sign-in attempts cannot exhaust memory.
var hashing = make(chan struct{}, 4)

// Pepper is a secret mixed into every password before hashing.
type Pepper struct {
	ID  string // derived from the secret; stored with each hash
	key []byte
}

// Peppers holds the current pepper and any previous ones still in use.
type Peppers struct {
	Current Pepper
	byID    map[string]Pepper
}

// MinPepperLength is the shortest pepper accepted, in characters.
const MinPepperLength = 32

// LoadPeppers reads the current pepper and any previous ones from files.
func LoadPeppers(current string, previous []string) (*Peppers, error) {
	ps := &Peppers{byID: map[string]Pepper{}}
	for i, path := range append([]string{current}, previous...) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("password pepper: %w", err)
		}
		secret := strings.TrimSpace(string(b))
		if len(secret) < MinPepperLength {
			return nil, fmt.Errorf("password pepper %s: must be at least %d characters; create one with as2d -generate-pepper", path, MinPepperLength)
		}
		p := NewPepper(secret)
		if i == 0 {
			ps.Current = p
		}
		ps.byID[p.ID] = p
	}
	return ps, nil
}

// NewPepper wraps a pepper secret.
func NewPepper(secret string) Pepper {
	sum := sha256.Sum256([]byte("as2d-pepper-id:" + secret))
	return Pepper{ID: hex.EncodeToString(sum[:8]), key: []byte(secret)}
}

// GeneratePepper returns a new random pepper secret (64 hex characters).
func GeneratePepper() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func derive(p Pepper, password string, salt []byte, t, m uint32, threads uint8) []byte {
	mac := hmac.New(sha256.New, p.key)
	mac.Write([]byte(password))
	hashing <- struct{}{}
	defer func() { <-hashing }()
	return argon2.IDKey(mac.Sum(nil), salt, t, m, threads, argonKeyLen)
}

var b64 = base64.RawStdEncoding

// Hash hashes a password with the current pepper. It returns the encoded
// hash and the pepper's ID, which must be stored together.
func (ps *Peppers) Hash(password string) (encoded, pepperID string) {
	salt := make([]byte, saltLen)
	rand.Read(salt)
	key := derive(ps.Current, password, salt, argonTime, argonMemory, argonThreads)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), ps.Current.ID
}

// Verify checks a password against an encoded hash made with the pepper
// pepperID. rehash reports that the password is right but the hash uses an
// old pepper or old parameters and should be replaced.
func (ps *Peppers) Verify(encoded, pepperID, password string) (ok, rehash bool) {
	p, known := ps.byID[pepperID]
	if !known {
		return false, false
	}
	var version int
	var m, t uint32
	var threads uint8
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false
	}
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &threads); err != nil {
		return false, false
	}
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false, false
	}
	got := derive(p, password, salt, t, m, threads)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false
	}
	return true, pepperID != ps.Current.ID || m != argonMemory || t != argonTime || threads != argonThreads
}

// burn spends the same effort as verifying a password, so a sign-in for an
// unknown user takes as long as one for a known user.
func (ps *Peppers) burn(password string) {
	derive(ps.Current, password, make([]byte, saltLen), argonTime, argonMemory, argonThreads)
}

// Password length limits. There are deliberately no composition rules;
// length is what makes a password strong (NIST SP 800-63B).
const (
	MinPasswordLength = 12
	MaxPasswordLength = 256
)

// CheckPassword reports why a new password is unacceptable, if it is.
func CheckPassword(username, password string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinPasswordLength:
		return fmt.Errorf("the password must be at least %d characters", MinPasswordLength)
	case n > MaxPasswordLength:
		return fmt.Errorf("the password must be at most %d characters", MaxPasswordLength)
	case strings.EqualFold(password, username):
		return errors.New("the password must not be the username")
	}
	return nil
}

// GeneratePassword returns a random one-time password, grouped for reading
// aloud, such as "kq7m-tz4w-9cxr-hb2n-v6pe".
func GeneratePassword() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789" // no l, o, 0, 1
	b := make([]byte, 20)
	rand.Read(b)
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return sb.String()
}
