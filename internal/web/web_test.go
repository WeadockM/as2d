package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/config"
	"github.com/WeadockM/as2d/internal/index"
)

func cert(t *testing.T, cn string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

type testSite struct {
	*httptest.Server
	dir string // the archived message's directory
}

func newSite(t *testing.T, token string) *testSite {
	t.Helper()
	root := t.TempDir()
	db, _, err := index.Open(filepath.Join(root, "as2d.db"), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := &archive.Store{Root: root, Index: db}
	meta, _ := json.Marshal(map[string]any{
		"message_id": "<m1@acme>", "as2_from": "ACME", "received": time.Now(), "filename": "po.edi", "payload_bytes": 5,
	})
	dir, err := store.Save("inbound", "ACME", "<m1@acme>", time.Now(), map[string][]byte{
		"meta.json": meta, "payload/po.edi": []byte("hello"), "request.http": []byte("POST /as2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(Config{
		Index: db,
		Local: as2.Station{ID: "US", Cert: cert(t, "US", time.Now().AddDate(1, 0, 0))},
		Partners: []Partner{
			{Config: &config.Partner{AS2ID: "ACME", RequireSignature: true,
				Outbound: &config.Outbound{URL: "https://acme.example/as2", Compress: "before-sign"}},
				Cert: cert(t, "ACME", time.Now().AddDate(0, 0, 10))},
			{Config: &config.Partner{AS2ID: "OLD"}, Cert: cert(t, "OLD", time.Now().Add(-time.Minute))},
		},
		Token: token, Log: slog.New(slog.DiscardHandler),
	})
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return &testSite{s, dir}
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestLoginAndCSRF(t *testing.T) {
	s := newSite(t, "s3cret")
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	if code, body := get(t, c, s.URL+"/api/session"); code != 200 || !strings.Contains(body, `"authenticated":false`) {
		t.Fatalf("session before login: %d %s", code, body)
	}
	if code, _ := get(t, c, s.URL+"/api/archive/messages"); code != http.StatusUnauthorized {
		t.Errorf("archive without login: %d", code)
	}
	resp, _ := c.Post(s.URL+"/api/login", "application/json", strings.NewReader(`{"token":"wrong"}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", resp.StatusCode)
	}
	resp, _ = c.Post(s.URL+"/api/login", "application/json", strings.NewReader(`{"token":"s3cret"}`))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	if code, body := get(t, c, s.URL+"/api/archive/messages"); code != 200 || !strings.Contains(body, "po.edi") {
		t.Errorf("archive after login: %d %s", code, body)
	}

	// A cookie-authenticated POST without the CSRF header is refused...
	resp, _ = c.Post(s.URL+"/api/messages/x/retry", "", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST without %s: %d", csrfHeader, resp.StatusCode)
	}
	// ...but gets past authentication with it (and finds no queue here).
	req, _ := http.NewRequest(http.MethodPost, s.URL+"/api/messages/x/retry", nil)
	req.Header.Set(csrfHeader, "1")
	resp, _ = c.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST with %s: %d", csrfHeader, resp.StatusCode)
	}

	// A bearer token works without a cookie, as for scripts.
	req, _ = http.NewRequest(http.MethodGet, s.URL+"/api/partners", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 200 {
		t.Errorf("bearer: %d", resp.StatusCode)
	}

	// A forged cookie is rejected.
	forged := &http.Client{}
	req, _ = http.NewRequest(http.MethodGet, s.URL+"/api/partners", nil)
	req.AddCookie(&http.Cookie{Name: tokenCookie, Value: "9999999999.deadbeef"})
	if resp, _ := forged.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("forged cookie: %d", resp.StatusCode)
	}
}

func TestArchiveViews(t *testing.T) {
	s := newSite(t, "") // no token: open, as on loopback
	c := http.DefaultClient

	var list struct {
		Total    int             `json:"total"`
		Messages []index.Message `json:"messages"`
		Partners []string        `json:"partners"`
	}
	_, body := get(t, c, s.URL+"/api/archive/messages?q=po&direction=inbound")
	json.Unmarshal([]byte(body), &list)
	if list.Total != 1 || list.Messages[0].Filename != "po.edi" || list.Partners[0] != "ACME" {
		t.Fatalf("list = %s", body)
	}
	id := list.Messages[0].ID

	code, body := get(t, c, s.URL+"/api/archive/messages/"+itoa(id))
	if code != 200 || !strings.Contains(body, `"path":"payload/po.edi"`) || !strings.Contains(body, `"meta":{`) {
		t.Errorf("detail: %d %s", code, body)
	}
	if code, body := get(t, c, s.URL+"/api/archive/messages/"+itoa(id)+"/files/payload/po.edi"); code != 200 || body != "hello" {
		t.Errorf("download: %d %q", code, body)
	}
	for _, bad := range []string{"../../../as2d.db", "payload/../../x", "nope.txt", "%2e%2e/as2d.db"} {
		if code, _ := get(t, c, s.URL+"/api/archive/messages/"+itoa(id)+"/files/"+bad); code == 200 {
			t.Errorf("download of %q succeeded", bad)
		}
	}
	if code, _ := get(t, c, s.URL+"/api/archive/messages/9999"); code != 404 {
		t.Errorf("unknown message: %d", code)
	}
	if code, _ := get(t, c, s.URL+"/api/archive/messages?since=yesterday"); code != 400 {
		t.Errorf("bad date: %d", code)
	}
}

func TestPartnersAndCerts(t *testing.T) {
	s := newSite(t, "")
	_, body := get(t, http.DefaultClient, s.URL+"/api/partners")
	var resp struct {
		Local struct {
			Cert certInfo `json:"cert"`
		} `json:"local"`
		Partners []struct {
			ID       string        `json:"id"`
			Cert     certInfo      `json:"cert"`
			Outbound *outboundInfo `json:"outbound"`
		} `json:"partners"`
	}
	json.Unmarshal([]byte(body), &resp)
	if resp.Local.Cert.Status != "ok" {
		t.Errorf("local cert status %q", resp.Local.Cert.Status)
	}
	if p := resp.Partners[0]; p.Cert.Status != "expiring" || p.Outbound == nil || p.Outbound.Cipher != "aes256-cbc" || p.Outbound.Compress != "before-sign" {
		t.Errorf("ACME = %+v", p)
	}
	if p := resp.Partners[1]; p.Cert.Status != "expired" || p.Outbound != nil {
		t.Errorf("OLD = %+v", p)
	}
	if code, body := get(t, http.DefaultClient, s.URL+"/api/certs/partners/ACME.pem"); code != 200 || !strings.HasPrefix(body, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("partner cert download: %d", code)
	}
	if code, _ := get(t, http.DefaultClient, s.URL+"/api/certs/local.pem"); code != 200 {
		t.Errorf("local cert download: %d", code)
	}
}

func TestStaticAndHeaders(t *testing.T) {
	s := newSite(t, "s3cret")
	resp, err := http.Get(s.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `<script src="app.js"`) {
		t.Errorf("index: %d", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP = %q", csp)
	}
	for _, f := range []string{"/app.js", "/style.css", "/favicon.svg"} {
		if code, _ := get(t, http.DefaultClient, s.URL+f); code != 200 {
			t.Errorf("%s: %d", f, code)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
