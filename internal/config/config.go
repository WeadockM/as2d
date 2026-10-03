// Package config loads the daemon's JSON configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/WeadockM/as2d/internal/as2"
)

type Config struct {
	// Inbound AS2 endpoint.
	Listen       string `json:"listen"`             // default ":4080"
	Path         string `json:"path"`               // default "/as2"
	TLSCert      string `json:"tls_cert,omitempty"` // serve HTTPS when both are set
	TLSKey       string `json:"tls_key,omitempty"`
	PublicURL    string `json:"public_url,omitempty"` // this endpoint as partners reach it; where async MDNs are sent
	MaxBodyBytes int64  `json:"max_body_bytes"`       // default 100 MiB

	ArchiveDir string `json:"archive_dir"`
	IndexDB    string `json:"index_db,omitempty"`   // SQLite index of the archive; default <archive_dir>/as2d.db
	InboxDir   string `json:"inbox_dir,omitempty"`  // received payloads are delivered here, per partner
	OutboxDir  string `json:"outbox_dir,omitempty"` // files dropped here, per partner, are sent
	SpoolDir   string `json:"spool_dir,omitempty"`  // outbound queue; required to send

	// Submission API for outbound messages. Off loopback it needs a token,
	// and should use TLS.
	APIListen  string `json:"api_listen,omitempty"` // e.g. "127.0.0.1:4090"
	APIToken   string `json:"api_token,omitempty"`  // required as a bearer token when set
	APITLSCert string `json:"api_tls_cert,omitempty"`
	APITLSKey  string `json:"api_tls_key,omitempty"`

	// Dashboard user accounts. Setting password_pepper_file turns them on;
	// users live in <state_dir>/state.db.
	StateDir            string   `json:"state_dir,omitempty"`
	PasswordPepperFile  string   `json:"password_pepper_file,omitempty"`
	PreviousPepperFiles []string `json:"previous_pepper_files,omitempty"` // still accepted while users move to the new pepper

	// StatusWebhook is told when each message to a partner is delivered or failed.
	StatusWebhook *Webhook `json:"status_webhook,omitempty"`

	// Outbound delivery tuning.
	Workers         int      `json:"workers,omitempty"`           // concurrent sends; default 4
	MaxAttempts     int      `json:"max_attempts,omitempty"`      // default 10
	AsyncMDNTimeout Duration `json:"async_mdn_timeout,omitempty"` // default 1h; then the message is resent
	SpoolRetention  Duration `json:"spool_retention,omitempty"`   // how long finished jobs stay queryable; default 168h

	Local    Station   `json:"local"`
	Partners []Partner `json:"partners"`
}

type Station struct {
	AS2ID string `json:"as2_id"`
	Cert  string `json:"cert"`
	Key   string `json:"key"`
}

type Partner struct {
	AS2ID             string    `json:"as2_id"`
	Cert              string    `json:"cert"`
	RequireEncryption bool      `json:"require_encryption"`
	RequireSignature  bool      `json:"require_signature"`
	Outbound          *Outbound `json:"outbound,omitempty"` // nil if we never send to this partner
	Forward           *Forward  `json:"forward,omitempty"`  // where received payloads are passed on
}

// Forward modes.
const (
	ForwardQueued    = "queued"     // MDN at once; forward from the queue with retries
	ForwardBeforeMDN = "before_mdn" // MDN only after the endpoint accepts the payload
)

// Forward passes a partner's received payloads to an HTTP endpoint such
// as a Boomi Web Services Server listener.
type Forward struct {
	URL          string   `json:"url"`
	Username     string   `json:"username,omitempty"` // HTTP Basic auth
	PasswordFile string   `json:"password_file,omitempty"`
	CAFile       string   `json:"ca_file,omitempty"` // extra trusted CA, e.g. for a self-signed Atom certificate
	Timeout      Duration `json:"timeout,omitzero"`  // default 60s
	Mode         string   `json:"mode,omitempty"`    // queued (default) or before_mdn
}

// Webhook is an HTTP endpoint that receives job status as JSON.
type Webhook struct {
	URL             string   `json:"url"`
	Username        string   `json:"username,omitempty"` // Basic auth, or
	PasswordFile    string   `json:"password_file,omitempty"`
	BearerTokenFile string   `json:"bearer_token_file,omitempty"` // a bearer token
	CAFile          string   `json:"ca_file,omitempty"`
	Timeout         Duration `json:"timeout,omitzero"` // default 30s
}

// Outbound says how to send messages to a partner. Unset booleans default
// to true.
type Outbound struct {
	URL         string `json:"url"`
	Encrypt     *bool  `json:"encrypt,omitempty"`
	Sign        *bool  `json:"sign,omitempty"`
	Cipher      string `json:"cipher,omitempty"`   // aes128-cbc, aes256-cbc (default), aes128-gcm, aes256-gcm
	MICAlg      string `json:"micalg,omitempty"`   // sha-1, sha-256 (default), sha-384, sha-512
	Compress    string `json:"compress,omitempty"` // none (default), before-sign or after-sign
	MDN         string `json:"mdn,omitempty"`      // sync (default), async or none
	SignedMDN   *bool  `json:"signed_mdn,omitempty"`
	AsyncMDNURL string `json:"async_mdn_url,omitempty"` // overrides public_url for this partner
}

// Bool returns *b, or true when it is unset.
func Bool(b *bool) bool { return b == nil || *b }

// SendOptions converts the partner's outbound settings. publicURL is used
// for async MDNs unless the partner overrides it.
func (o *Outbound) SendOptions(publicURL string) as2.SendOptions {
	opts := as2.SendOptions{
		Encrypt:    Bool(o.Encrypt),
		Sign:       Bool(o.Sign),
		SignedMDN:  Bool(o.SignedMDN),
		Cipher:     o.Cipher,
		MICAlg:     o.MICAlg,
		RequestMDN: o.MDN != "none",
	}
	if o.Compress != "none" {
		opts.Compress = o.Compress
	}
	if o.MDN == "async" {
		opts.AsyncMDNURL = o.AsyncMDNURL
		if opts.AsyncMDNURL == "" {
			opts.AsyncMDNURL = publicURL
		}
	}
	return opts
}

// Duration is a time.Duration written as a string such as "90m" in JSON.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string such as \"1h30m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// Load reads and validates a configuration file. Relative file paths in it
// are resolved against the directory containing the file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = ":4080"
	}
	if c.Path == "" {
		c.Path = "/as2"
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 100 << 20
	}
	if c.Workers == 0 {
		c.Workers = 4
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 10
	}
	if c.AsyncMDNTimeout.Duration == 0 {
		c.AsyncMDNTimeout.Duration = time.Hour
	}
	if c.SpoolRetention.Duration == 0 {
		c.SpoolRetention.Duration = 7 * 24 * time.Hour
	}

	base := filepath.Dir(path)
	paths := []*string{&c.TLSCert, &c.TLSKey, &c.APITLSCert, &c.APITLSKey, &c.ArchiveDir, &c.IndexDB, &c.InboxDir,
		&c.OutboxDir, &c.SpoolDir, &c.StateDir, &c.PasswordPepperFile, &c.Local.Cert, &c.Local.Key}
	for i := range c.PreviousPepperFiles {
		paths = append(paths, &c.PreviousPepperFiles[i])
	}
	if w := c.StatusWebhook; w != nil {
		paths = append(paths, &w.PasswordFile, &w.BearerTokenFile, &w.CAFile)
		if w.Timeout.Duration == 0 {
			w.Timeout.Duration = 30 * time.Second
		}
	}
	for i := range c.Partners {
		p := &c.Partners[i]
		p.ApplyDefaults()
		paths = append(paths, &p.Cert)
		if f := p.Forward; f != nil {
			paths = append(paths, &f.PasswordFile, &f.CAFile)
		}
	}
	for _, p := range paths {
		*p = resolve(base, *p)
	}
	if c.IndexDB == "" && c.ArchiveDir != "" {
		c.IndexDB = filepath.Join(c.ArchiveDir, "as2d.db")
	}

	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// StateDB is the user account database.
func (c *Config) StateDB() string { return filepath.Join(c.StateDir, "state.db") }

// NeedsQueue reports whether the outbound queue is needed: some partner is
// sent to, or forwards in queued mode.
func (c *Config) NeedsQueue() bool {
	for _, p := range c.Partners {
		if p.Outbound != nil || (p.Forward != nil && p.Forward.Mode == ForwardQueued) {
			return true
		}
	}
	return false
}

func (c *Config) validate() error {
	var errs []error
	if (c.TLSCert == "") != (c.TLSKey == "") {
		errs = append(errs, errors.New("tls_cert and tls_key must be set together"))
	}
	if (c.APITLSCert == "") != (c.APITLSKey == "") {
		errs = append(errs, errors.New("api_tls_cert and api_tls_key must be set together"))
	}
	if c.PasswordPepperFile != "" && c.StateDir == "" {
		errs = append(errs, errors.New("password_pepper_file needs state_dir, where user accounts are kept"))
	}
	if len(c.PreviousPepperFiles) > 0 && c.PasswordPepperFile == "" {
		errs = append(errs, errors.New("previous_pepper_files needs password_pepper_file"))
	}
	if w := c.StatusWebhook; w != nil {
		if w.URL == "" {
			errs = append(errs, errors.New("status_webhook: url is required"))
		}
		if w.BearerTokenFile != "" && w.Username != "" {
			errs = append(errs, errors.New("status_webhook: use either bearer_token_file or username/password_file"))
		}
	}
	if c.Local.AS2ID == "" || c.Local.Cert == "" || c.Local.Key == "" {
		errs = append(errs, errors.New("local.as2_id, local.cert and local.key are required"))
	}
	seen := map[string]bool{}
	for i, p := range c.Partners {
		if seen[p.AS2ID] {
			errs = append(errs, fmt.Errorf("partners[%d]: duplicate as2_id %q", i, p.AS2ID))
		}
		seen[p.AS2ID] = true
		if p.AS2ID == c.Local.AS2ID && p.AS2ID != "" {
			errs = append(errs, fmt.Errorf("partners[%d]: as2_id %q is the local station's", i, p.AS2ID))
		}
		if err := p.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("partners[%d]: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

// CheckAS2ID reports why an AS2 identifier is unacceptable, if it is.
// RFC 4130 allows 1 to 128 printable ASCII characters; quotes and
// backslashes are refused because they need escaping in headers.
func CheckAS2ID(id string) error {
	switch {
	case id == "":
		return errors.New("as2_id is required")
	case len(id) > 128:
		return errors.New("as2_id must be at most 128 characters")
	case strings.TrimSpace(id) != id:
		return errors.New("as2_id must not start or end with a space")
	}
	for _, r := range id {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return fmt.Errorf("as2_id may only contain printable ASCII characters other than \" and \\")
		}
	}
	return nil
}

// ApplyDefaults fills in the forward mode and timeout when unset.
func (p *Partner) ApplyDefaults() {
	if f := p.Forward; f != nil {
		if f.Mode == "" {
			f.Mode = ForwardQueued
		}
		if f.Timeout.Duration == 0 {
			f.Timeout.Duration = 60 * time.Second
		}
	}
}

// Validate checks a partner's settings, apart from whether its certificate
// file exists and parses.
func (p *Partner) Validate() error {
	var errs []error
	if err := CheckAS2ID(p.AS2ID); err != nil {
		errs = append(errs, err)
	}
	if p.Cert == "" {
		errs = append(errs, errors.New("cert is required"))
	}
	if o := p.Outbound; o != nil {
		if u, err := url.Parse(o.URL); o.URL == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, errors.New("outbound: url is required and must be an http:// or https:// address"))
		}
		switch o.MDN {
		case "", "sync", "async", "none":
		default:
			errs = append(errs, errors.New("outbound: mdn must be sync, async or none"))
		}
		switch o.Compress {
		case "", "none", as2.CompressBeforeSign, as2.CompressAfterSign:
		default:
			errs = append(errs, errors.New("outbound: compress must be none, before-sign or after-sign"))
		}
		if o.Cipher != "" {
			if _, ok := as2.Ciphers[o.Cipher]; !ok {
				errs = append(errs, fmt.Errorf("outbound: unknown cipher %q", o.Cipher))
			}
		}
		switch o.MICAlg {
		case "", "sha-1", "sha-256", "sha-384", "sha-512":
		default:
			errs = append(errs, fmt.Errorf("outbound: micalg must be sha-1, sha-256, sha-384 or sha-512, not %q", o.MICAlg))
		}
	}
	if f := p.Forward; f != nil {
		if f.URL == "" {
			errs = append(errs, errors.New("forward: url is required"))
		}
		if f.Mode != ForwardQueued && f.Mode != ForwardBeforeMDN {
			errs = append(errs, errors.New("forward: mode must be queued or before_mdn"))
		}
		if (f.Username == "") != (f.PasswordFile == "") {
			errs = append(errs, errors.New("forward: username and password_file go together"))
		}
	}
	return errors.Join(errs...)
}

func resolve(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}
