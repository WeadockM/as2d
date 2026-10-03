// Package web serves the dashboard: a browser UI plus the JSON endpoints it
// uses to browse the archive, partners and certificates. It shares the API
// listener and token with the outbound API.
package web

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/config"
	"github.com/WeadockM/as2d/internal/index"
	"github.com/WeadockM/as2d/internal/outbound"
)

//go:embed static
var static embed.FS

// ExpiryWarning is how close to expiry a certificate is flagged.
const ExpiryWarning = 30 * 24 * time.Hour

// Partner is what the dashboard shows about a trading partner.
type Partner struct {
	Config *config.Partner
	Cert   *x509.Certificate
}

type Config struct {
	Index    *index.DB
	Queue    *outbound.Manager // nil when nothing is sent or forwarded
	Local    as2.Station
	Partners []Partner
	Token    string // empty: no login (loopback only; enforced by the caller)
	Secure   bool   // served over TLS; marks the session cookie Secure
	MaxBody  int64
	Log      *slog.Logger
}

// Handler returns the dashboard and its API, including the outbound API
// when there is a queue.
func Handler(cfg Config) http.Handler {
	s := &site{cfg: cfg, auth: newAuth(cfg.Token, cfg.Secure)}
	api := http.NewServeMux()
	api.HandleFunc("GET /api/archive/messages", s.listMessages)
	api.HandleFunc("GET /api/archive/messages/{id}", s.getMessage)
	api.HandleFunc("GET /api/archive/messages/{id}/files/{file...}", s.getFile)
	api.HandleFunc("GET /api/partners", s.partners)
	api.HandleFunc("GET /api/certs/local.pem", s.localCert)
	api.HandleFunc("GET /api/certs/partners/{id}", s.partnerCert)
	if cfg.Queue != nil {
		q := cfg.Queue.APIHandler("", cfg.MaxBody) // authentication happens here, not in it
		api.Handle("/api/messages", q)
		api.Handle("/api/messages/", q)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", s.session)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.Handle("/api/", s.auth.require(api))
	sub, _ := fs.Sub(static, "static")
	mux.Handle("/", http.FileServerFS(sub))
	return securityHeaders(mux)
}

type site struct {
	cfg  Config
	auth *auth
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

func (s *site) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_required":   s.auth.token != "",
		"authenticated":   s.auth.ok(r),
		"local_id":        s.cfg.Local.ID,
		"sending_enabled": s.cfg.Queue != nil,
	})
}

func (s *site) listMessages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := index.Filter{
		Direction: q.Get("direction"),
		Partner:   q.Get("partner"),
		State:     q.Get("state"),
		Search:    strings.TrimSpace(q.Get("q")),
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	for key, dst := range map[string]*time.Time{"since": &f.Since, "until": &f.Until} {
		if v := q.Get(key); v != "" {
			t, err := parseTime(v)
			if err != nil {
				apiError(w, http.StatusBadRequest, key+": use a date (2026-10-02) or RFC 3339 time")
				return
			}
			*dst = t
		}
	}
	msgs, total, err := s.cfg.Index.List(f)
	if err != nil {
		s.cfg.Log.Error("archive query failed", "err", err)
		apiError(w, http.StatusInternalServerError, "archive query failed")
		return
	}
	partners, _ := s.cfg.Index.Partners()
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "messages": msgs, "partners": partners})
}

func parseTime(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", v)
}

type file struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

func (s *site) message(w http.ResponseWriter, r *http.Request) (index.Message, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		apiError(w, http.StatusNotFound, "no such message")
		return index.Message{}, false
	}
	m, err := s.cfg.Index.Get(id)
	if err != nil {
		apiError(w, http.StatusNotFound, "no such message")
		return index.Message{}, false
	}
	return m, true
}

// files lists the files in a message directory, slash-separated.
func files(dir string) []file {
	var out []file
	filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		info, err := e.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, file{filepath.ToSlash(rel), info.Size()})
		return nil
	})
	return out
}

func (s *site) getMessage(w http.ResponseWriter, r *http.Request) {
	m, ok := s.message(w, r)
	if !ok {
		return
	}
	var meta json.RawMessage
	if b, err := os.ReadFile(filepath.Join(m.ArchiveDir, "meta.json")); err == nil && json.Valid(b) {
		meta = b
	}
	resp := map[string]any{"message": m, "meta": meta, "files": files(m.ArchiveDir)}
	if s.cfg.Queue != nil && m.JobID != "" {
		if j, ok := s.cfg.Queue.Get(m.JobID); ok {
			resp["job"] = j.Status()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *site) getFile(w http.ResponseWriter, r *http.Request) {
	m, ok := s.message(w, r)
	if !ok {
		return
	}
	// Only files that are actually in the message directory, by exact name.
	want := path.Clean(r.PathValue("file"))
	if !slices.ContainsFunc(files(m.ArchiveDir), func(f file) bool { return f.Path == want }) {
		apiError(w, http.StatusNotFound, "no such file")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(path.Base(want), `"`, "")+`"`)
	http.ServeFile(w, r, filepath.Join(m.ArchiveDir, filepath.FromSlash(want)))
}

// certInfo is a certificate as the dashboard shows it.
type certInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	Serial     string    `json:"serial"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DaysLeft   int       `json:"days_left"`
	Status     string    `json:"status"` // ok, expiring or expired
	SHA256     string    `json:"sha256"`
	SelfSigned bool      `json:"self_signed"`
}

// CertStatus classifies a certificate's expiry: ok, expiring or expired.
func CertStatus(c *x509.Certificate, now time.Time) string {
	switch {
	case now.After(c.NotAfter) || now.Before(c.NotBefore):
		return "expired"
	case c.NotAfter.Sub(now) < ExpiryWarning:
		return "expiring"
	}
	return "ok"
}

func describeCert(c *x509.Certificate) *certInfo {
	if c == nil {
		return nil
	}
	now := time.Now()
	sum := sha256.Sum256(c.Raw)
	return &certInfo{
		Subject:    c.Subject.String(),
		Issuer:     c.Issuer.String(),
		Serial:     c.SerialNumber.Text(16),
		NotBefore:  c.NotBefore,
		NotAfter:   c.NotAfter,
		DaysLeft:   int(c.NotAfter.Sub(now).Hours() / 24),
		Status:     CertStatus(c, now),
		SHA256:     strings.ToUpper(hex.EncodeToString(sum[:])),
		SelfSigned: c.Subject.String() == c.Issuer.String(),
	}
}

type outboundInfo struct {
	URL       string `json:"url"`
	Encrypt   bool   `json:"encrypt"`
	Sign      bool   `json:"sign"`
	Cipher    string `json:"cipher"`
	MICAlg    string `json:"micalg"`
	Compress  string `json:"compress"`
	MDN       string `json:"mdn"`
	SignedMDN bool   `json:"signed_mdn"`
}

type forwardInfo struct {
	URL      string `json:"url"`
	Mode     string `json:"mode"`
	Username string `json:"username,omitempty"`
}

func (s *site) partners(w http.ResponseWriter, r *http.Request) {
	type partnerOut struct {
		ID                string        `json:"id"`
		Cert              *certInfo     `json:"cert"`
		RequireEncryption bool          `json:"require_encryption"`
		RequireSignature  bool          `json:"require_signature"`
		Outbound          *outboundInfo `json:"outbound"`
		Forward           *forwardInfo  `json:"forward"`
	}
	out := []partnerOut{}
	for _, p := range s.cfg.Partners {
		po := partnerOut{
			ID: p.Config.AS2ID, Cert: describeCert(p.Cert),
			RequireEncryption: p.Config.RequireEncryption, RequireSignature: p.Config.RequireSignature,
		}
		if o := p.Config.Outbound; o != nil {
			po.Outbound = &outboundInfo{
				URL: o.URL, Encrypt: config.Bool(o.Encrypt), Sign: config.Bool(o.Sign), SignedMDN: config.Bool(o.SignedMDN),
				Cipher: or(o.Cipher, "aes256-cbc"), MICAlg: or(o.MICAlg, "sha-256"), Compress: or(o.Compress, "none"), MDN: or(o.MDN, "sync"),
			}
		}
		if f := p.Config.Forward; f != nil {
			po.Forward = &forwardInfo{URL: f.URL, Mode: f.Mode, Username: f.Username}
		}
		out = append(out, po)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"local":    map[string]any{"id": s.cfg.Local.ID, "cert": describeCert(s.cfg.Local.Cert)},
		"partners": out,
	})
}

func (s *site) localCert(w http.ResponseWriter, r *http.Request) {
	servePEM(w, s.cfg.Local.ID, s.cfg.Local.Cert)
}

func (s *site) partnerCert(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(r.PathValue("id"), ".pem")
	for _, p := range s.cfg.Partners {
		if p.Config.AS2ID == id {
			servePEM(w, id, p.Cert)
			return
		}
	}
	apiError(w, http.StatusNotFound, "no such partner")
}

func servePEM(w http.ResponseWriter, name string, c *x509.Certificate) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename(name)+`.crt"`)
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func safeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x80 && (r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return r
		}
		return '_'
	}, s)
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

var errBadLogin = errors.New("wrong token")
