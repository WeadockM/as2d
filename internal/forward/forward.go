// Package forward hands received payloads to a downstream HTTP endpoint
// (such as a Boomi Web Services Server listener) and posts status callbacks.
package forward

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Target is an endpoint that accepts payloads, authenticated with HTTP
// Basic auth when Username is set.
type Target struct {
	URL      string
	Username string
	Password string
	Client   *http.Client
}

// Message is a received payload and the AS2 details passed along with it.
type Message struct {
	From, To, MessageID, Filename, Subject, ContentType string
	Payload                                             []byte
}

// Error is a failed forward. Retryable reports whether sending again could
// succeed (network errors, 5xx, 408, 429), as opposed to a rejection.
type Error struct {
	Status    int // 0 when no response was received
	Retryable bool
	Err       error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Send POSTs the payload with its own Content-Type and the AS2 details as
// X-AS2-* headers. It returns the HTTP status, and an *Error unless it was 2xx.
func (t *Target) Send(ctx context.Context, m Message) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(m.Payload))
	if err != nil {
		return 0, &Error{Err: err}
	}
	ct := m.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	req.Header.Set("Content-Type", ct)
	for k, v := range map[string]string{
		"X-AS2-From":       m.From,
		"X-AS2-To":         m.To,
		"X-AS2-Message-ID": m.MessageID,
		"X-AS2-Filename":   m.Filename,
		"X-AS2-Subject":    m.Subject,
	} {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	if t.Username != "" {
		req.SetBasicAuth(t.Username, t.Password)
	}
	return do(t.Client, req)
}

// Webhook receives job status callbacks, authenticated with a bearer token
// or Basic auth.
type Webhook struct {
	URL         string
	Username    string
	Password    string
	BearerToken string
	Client      *http.Client
}

// Post sends v as JSON.
func (w *Webhook) Post(ctx context.Context, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case w.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+w.BearerToken)
	case w.Username != "":
		req.SetBasicAuth(w.Username, w.Password)
	}
	_, err = do(w.Client, req)
	return err
}

func do(c *http.Client, req *http.Request) (int, error) {
	resp, err := c.Do(req)
	if err != nil {
		return 0, &Error{Retryable: true, Err: err}
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 == 2 {
		return resp.StatusCode, nil
	}
	code := resp.StatusCode
	return code, &Error{
		Status:    code,
		Retryable: code >= 500 || code == http.StatusRequestTimeout || code == http.StatusTooManyRequests,
		Err:       fmt.Errorf("%s responded %s: %s", req.URL.Host, resp.Status, firstLine(snippet)),
	}
}

// NewClient returns an HTTP client with the given timeout. If caFile is
// set, its PEM certificates are trusted in addition to the system roots,
// e.g. for an Atom using an internal CA or a self-signed certificate.
func NewClient(caFile string, timeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no PEM certificates found", caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: timeout, Transport: transport}, nil
}

// ReadSecret reads a password or token from a file, ignoring surrounding
// whitespace such as a trailing newline.
func ReadSecret(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New(path + ": file is empty")
	}
	return s, nil
}

func firstLine(b []byte) string {
	line, _, _ := bytes.Cut(bytes.TrimSpace(b), []byte("\n"))
	if len(line) > 200 {
		line = line[:200]
	}
	return string(line)
}
