// Package partners manages trading partners: those defined in config.json
// and those added through the dashboard, which are kept as files under
// <state_dir>/partners with a version history. It builds the combined set
// and applies it to the running daemon without a restart.
package partners

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/config"
)

// Record is a dashboard-managed partner: the settings of config.Partner
// except the certificate, which is stored beside it, plus who changed it.
type Record struct {
	AS2ID             string           `json:"as2_id"`
	RequireEncryption bool             `json:"require_encryption"`
	RequireSignature  bool             `json:"require_signature"`
	Outbound          *config.Outbound `json:"outbound,omitempty"`
	Forward           *config.Forward  `json:"forward,omitempty"`

	Version   int       `json:"version"`
	Updated   time.Time `json:"updated"`
	UpdatedBy string    `json:"updated_by"`
	Action    string    `json:"action"` // created, updated, deleted, imported from config.json, restored version N
}

// Partner returns the record as a config.Partner using certPath.
func (r Record) Partner(certPath string) config.Partner {
	p := config.Partner{
		AS2ID: r.AS2ID, Cert: certPath,
		RequireEncryption: r.RequireEncryption, RequireSignature: r.RequireSignature,
		Outbound: r.Outbound, Forward: r.Forward,
	}
	p.ApplyDefaults()
	return p
}

// ErrNotFound is returned for a partner or version that doesn't exist.
var ErrNotFound = errors.New("no such partner in the dashboard")

// Store keeps dashboard partners as files:
//
//	<dir>/<name>.json, <dir>/<name>.crt              current version
//	<dir>/.history/<name>/<version>.json, .crt       every version, including the current
type Store struct {
	dir string
	mu  sync.Mutex
}

// OpenStore opens (creating if needed) the partner store in dir.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, ".history"), 0o750); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// fileName maps an AS2 ID to a safe, unique file name.
func fileName(id string) string {
	name := archive.SafeName(id)
	if name != id {
		sum := sha256.Sum256([]byte(id))
		name += "_" + hex.EncodeToString(sum[:4])
	}
	return name
}

func (s *Store) paths(id string) (record, cert string) {
	base := filepath.Join(s.dir, fileName(id))
	return base + ".json", base + ".crt"
}

func (s *Store) historyDir(id string) string {
	return filepath.Join(s.dir, ".history", fileName(id))
}

func readRecord(path string) (Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Record{}, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return Record{}, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// List returns the current dashboard partners, by AS2 ID.
func (s *Store) List() ([]Record, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		r, err := readRecord(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Record) int { return strings.Compare(a.AS2ID, b.AS2ID) })
	return out, nil
}

// Get returns a dashboard partner and its certificate (PEM).
func (s *Store) Get(id string) (Record, []byte, error) {
	recPath, certPath := s.paths(id)
	r, err := readRecord(recPath)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, nil, ErrNotFound
	}
	if err != nil {
		return Record{}, nil, err
	}
	cert, err := os.ReadFile(certPath)
	return r, cert, err
}

// CertPath is where a dashboard partner's certificate is kept.
func (s *Store) CertPath(id string) string {
	_, cert := s.paths(id)
	return cert
}

// put writes a new version of a partner. certPEM must be the complete
// certificate to store. It returns the stored record.
func (s *Store) put(r Record, certPEM []byte, by, action string) (Record, error) {
	if block, _ := pem.Decode(certPEM); block == nil || block.Type != "CERTIFICATE" {
		return Record{}, errors.New("the certificate must be PEM encoded")
	}
	recPath, certPath := s.paths(r.AS2ID)
	r.Version = s.latestVersion(r.AS2ID) + 1
	r.Updated, r.UpdatedBy, r.Action = time.Now().UTC(), by, action
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return Record{}, err
	}
	// History first: if writing the current files fails, the version is
	// still recorded and the next save simply supersedes it.
	hist := s.historyDir(r.AS2ID)
	if err := os.MkdirAll(hist, 0o750); err != nil {
		return Record{}, err
	}
	v := strconv.Itoa(r.Version)
	for path, content := range map[string][]byte{
		filepath.Join(hist, v+".crt"): certPEM, filepath.Join(hist, v+".json"): data,
		certPath: certPEM, recPath: data,
	} {
		if err := archive.WriteFileAtomic(path, content); err != nil {
			return Record{}, err
		}
	}
	return r, nil
}

// remove deletes a partner, keeping its history with a final "deleted"
// entry.
func (s *Store) remove(id, by string) error {
	r, cert, err := s.Get(id)
	if err != nil {
		return err
	}
	r.Version = s.latestVersion(id) + 1
	r.Updated, r.UpdatedBy, r.Action = time.Now().UTC(), by, "deleted"
	data, _ := json.MarshalIndent(r, "", "  ")
	hist, v := s.historyDir(id), strconv.Itoa(r.Version)
	if err := archive.WriteFileAtomic(filepath.Join(hist, v+".json"), data); err != nil {
		return err
	}
	archive.WriteFileAtomic(filepath.Join(hist, v+".crt"), cert)
	recPath, certPath := s.paths(id)
	if err := os.Remove(recPath); err != nil {
		return err
	}
	os.Remove(certPath)
	return nil
}

func (s *Store) latestVersion(id string) int {
	entries, _ := os.ReadDir(s.historyDir(id))
	latest := 0
	for _, e := range entries {
		if v, err := strconv.Atoi(strings.TrimSuffix(e.Name(), ".json")); err == nil && strings.HasSuffix(e.Name(), ".json") {
			latest = max(latest, v)
		}
	}
	return latest
}

// History returns every version of a partner, newest first. It includes
// partners that have since been deleted.
func (s *Store) History(id string) ([]Record, error) {
	entries, err := os.ReadDir(s.historyDir(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			r, err := readRecord(filepath.Join(s.historyDir(id), e.Name()))
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b Record) int { return b.Version - a.Version })
	return out, nil
}

// Version returns one version of a partner and its certificate.
func (s *Store) Version(id string, version int) (Record, []byte, error) {
	base := filepath.Join(s.historyDir(id), strconv.Itoa(version))
	r, err := readRecord(base + ".json")
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, nil, ErrNotFound
	}
	if err != nil {
		return Record{}, nil, err
	}
	cert, err := os.ReadFile(base + ".crt")
	return r, cert, err
}
