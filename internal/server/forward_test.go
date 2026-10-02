package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/forward"
	"github.com/WeadockM/as2d/internal/outbound"
)

// fakeBoomi stands in for a Boomi Web Services Server listener.
type fakeBoomi struct {
	*httptest.Server
	down atomic.Int32 // requests left to answer with 503

	mu       sync.Mutex
	received []boomiRequest
}

type boomiRequest struct {
	header       http.Header
	body         string
	user, pass   string
	hasBasicAuth bool
}

func newFakeBoomi(t *testing.T) *fakeBoomi {
	b := &fakeBoomi{}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.down.Add(-1) >= 0 {
			http.Error(w, "Atom unavailable", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		user, pass, ok := r.BasicAuth()
		b.mu.Lock()
		b.received = append(b.received, boomiRequest{r.Header.Clone(), string(body), user, pass, ok})
		b.mu.Unlock()
	}))
	t.Cleanup(b.Close)
	return b
}

func (b *fakeBoomi) requests() []boomiRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]boomiRequest(nil), b.received...)
}

func (b *fakeBoomi) target() *forward.Target {
	return &forward.Target{URL: b.URL + "/ws/simple/executeInboundAS2", Username: "boomi-user@account-1234",
		Password: "s3cret", Client: &http.Client{Timeout: 5 * time.Second}}
}

func (f *fixture) postSigned(t *testing.T, messageID string) *httptest.ResponseRecorder {
	ct, body := f.sign(t, payloadEntity)
	headers := map[string]string{"Message-ID": messageID}
	for k, v := range unsignedMDN {
		headers[k] = v
	}
	return f.post(ct, []byte(body), headers)
}

func readMeta(t *testing.T, dir string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func archivedDirs(t *testing.T, f *fixture) []string {
	dirs, _ := filepath.Glob(filepath.Join(f.root, "inbound", "PARTNER", "*", "*", "*", "*"))
	return dirs
}

func checkBoomiRequest(t *testing.T, r boomiRequest, messageID string) {
	t.Helper()
	if !r.hasBasicAuth || r.user != "boomi-user@account-1234" || r.pass != "s3cret" {
		t.Errorf("basic auth = %q/%q (%v)", r.user, r.pass, r.hasBasicAuth)
	}
	if r.body != payload {
		t.Errorf("body = %q", r.body)
	}
	for k, want := range map[string]string{
		"Content-Type":     "application/edi-x12",
		"X-AS2-From":       "PARTNER",
		"X-AS2-To":         "LOCAL",
		"X-AS2-Message-ID": messageID,
		"X-AS2-Filename":   "po.edi",
	} {
		if got := r.header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestForwardBeforeMDN(t *testing.T) {
	f := newFixture(t)
	boomi := newFakeBoomi(t)
	f.srv.Forwards = map[string]*ForwardRule{"PARTNER": {Target: boomi.target(), BeforeMDN: true}}

	rec := f.postSigned(t, "<fwd-1@partner>")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "; processed\r\n") {
		t.Fatalf("status %d:\n%s", rec.Code, rec.Body)
	}
	reqs := boomi.requests()
	if len(reqs) != 1 {
		t.Fatalf("Boomi got %d requests, want 1", len(reqs))
	}
	checkBoomiRequest(t, reqs[0], "<fwd-1@partner>")
	fwd, _ := readMeta(t, f.archived(t))["forward"].(map[string]any)
	if fwd["mode"] != "before_mdn" || fwd["http_status"] != float64(200) {
		t.Errorf("meta.json forward = %v", fwd)
	}
}

// TestForwardBeforeMDNBoomiDown: the partner gets a 500 and no MDN, so it
// resends; once Boomi accepts the message, later copies are duplicates.
func TestForwardBeforeMDNBoomiDown(t *testing.T) {
	f := newFixture(t)
	boomi := newFakeBoomi(t)
	boomi.down.Store(1)
	f.srv.Forwards = map[string]*ForwardRule{"PARTNER": {Target: boomi.target(), BeforeMDN: true}}

	rec := f.postSigned(t, "<fwd-2@partner>")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "Disposition") {
		t.Fatalf("Boomi down: status %d, body:\n%s", rec.Code, rec.Body)
	}
	if fwd, _ := readMeta(t, f.archived(t))["forward"].(map[string]any); fwd["http_status"] != float64(503) || fwd["error"] == nil {
		t.Errorf("meta.json forward after failure = %v", fwd)
	}

	// The partner resends: now Boomi is up.
	if rec := f.postSigned(t, "<fwd-2@partner>"); !strings.Contains(rec.Body.String(), "; processed\r\n") {
		t.Fatalf("resend:\n%s", rec.Body)
	}
	// A further copy is a duplicate and is not forwarded again.
	if rec := f.postSigned(t, "<fwd-2@partner>"); !strings.Contains(rec.Body.String(), "duplicate-document") {
		t.Fatalf("third copy:\n%s", rec.Body)
	}
	if n := len(boomi.requests()); n != 1 {
		t.Errorf("Boomi accepted %d copies, want 1", n)
	}
	if n := len(archivedDirs(t, f)); n != 3 {
		t.Errorf("%d archived copies, want 3", n)
	}
}

// TestForwardQueuedBoomiDown: the partner gets its MDN at once, and the
// queue keeps retrying until Boomi takes the payload.
func TestForwardQueuedBoomiDown(t *testing.T) {
	f := newFixture(t)
	boomi := newFakeBoomi(t)
	boomi.down.Store(2)
	target := boomi.target()

	mgr, err := outbound.New(outbound.Config{
		Local:       as2.Station{ID: "LOCAL", Cert: f.local.cert, Key: f.local.key},
		Partners:    map[string]*outbound.Partner{},
		SpoolDir:    t.TempDir(),
		Archive:     f.srv.Archive,
		Log:         slog.New(slog.DiscardHandler),
		Workers:     1,
		MaxAttempts: 5,
		Backoff:     func(int) time.Duration { return 10 * time.Millisecond },
		Forwards:    map[string]*forward.Target{"PARTNER": target},
	})
	if err != nil {
		t.Fatal(err)
	}
	go mgr.Run(t.Context())
	f.srv.Forwards = map[string]*ForwardRule{"PARTNER": {Target: target}}
	f.srv.Queue = mgr

	rec := f.postSigned(t, "<fwd-3@partner>")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "; processed\r\n") {
		t.Fatalf("MDN should not wait for Boomi: status %d:\n%s", rec.Code, rec.Body)
	}

	dir := f.archived(t)
	deadline := time.Now().Add(10 * time.Second)
	var fwd map[string]any
	for time.Now().Before(deadline) {
		fwd, _ = readMeta(t, dir)["forward"].(map[string]any)
		if fwd["state"] == "delivered" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if fwd["state"] != "delivered" || fwd["attempts"] != float64(3) || fwd["mode"] != "queued" {
		t.Fatalf("meta.json forward = %v", fwd)
	}
	reqs := boomi.requests()
	if len(reqs) != 1 {
		t.Fatalf("Boomi accepted %d requests, want 1", len(reqs))
	}
	checkBoomiRequest(t, reqs[0], "<fwd-3@partner>")
}
