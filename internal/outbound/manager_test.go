package outbound

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
)

func newStation(t *testing.T, id string) as2.Station {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: id},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return as2.Station{ID: id, Cert: cert, Key: key}
}

// partnerServer is a fake partner: an as2.Receiver behind HTTP. fail makes
// it return 503 for that many requests first.
type partnerServer struct {
	*httptest.Server
	rcv      *as2.Receiver
	requests atomic.Int32
	fail     atomic.Int32
	async    chan *as2.MDN  // async MDNs are handed here instead of posted
	early    func(*as2.MDN) // if set, called with the async MDN before responding
}

func newPartner(t *testing.T, us, them as2.Station) *partnerServer {
	ps := &partnerServer{
		rcv:   &as2.Receiver{Local: them, Partners: map[string]*as2.Partner{us.ID: {ID: us.ID, Cert: us.Cert}}},
		async: make(chan *as2.MDN, 4),
	}
	ps.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ps.requests.Add(1) <= ps.fail.Load() {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		msg, err := ps.rcv.Process(r.Header, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		mdn, err := ps.rcv.BuildMDN(msg)
		if err != nil {
			t.Error(err)
			return
		}
		if msg.Receipt.AsyncURL != "" {
			if ps.early != nil {
				ps.early(mdn)
			} else {
				ps.async <- mdn
			}
			return
		}
		for k, v := range mdn.Header {
			w.Header()[k] = v
		}
		w.Write(mdn.Body)
	}))
	t.Cleanup(ps.Close)
	return ps
}

func newManager(t *testing.T, us, them as2.Station, url string, opts as2.SendOptions, mods ...func(*Config)) *Manager {
	t.Helper()
	cfg := Config{
		Local:       us,
		Partners:    map[string]*Partner{them.ID: {Partner: &as2.Partner{ID: them.ID, Cert: them.Cert}, URL: url, Options: opts}},
		SpoolDir:    t.TempDir(),
		Archive:     &archive.Store{Root: t.TempDir()},
		Log:         slog.New(slog.DiscardHandler),
		Workers:     2,
		MaxAttempts: 3,
		MDNTimeout:  time.Hour,
		Retention:   time.Hour,
		Backoff:     func(int) time.Duration { return 10 * time.Millisecond },
	}
	for _, mod := range mods {
		mod(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return m
}

func waitFor(t *testing.T, m *Manager, id string, states ...State) Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := m.Get(id)
		for _, s := range states {
			if j.State == s {
				return j
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	j, _ := m.Get(id)
	t.Fatalf("job stuck in %s (last error %q)", j.State, j.LastError)
	return j
}

var fullSecurity = as2.SendOptions{Sign: true, Encrypt: true, RequestMDN: true, SignedMDN: true, Compress: as2.CompressBeforeSign}

func TestDeliverWithRetries(t *testing.T) {
	us, them := newStation(t, "US"), newStation(t, "THEM")
	ps := newPartner(t, us, them)
	ps.fail.Store(2) // two 503s, then success
	m := newManager(t, us, them, ps.URL, fullSecurity)

	job, err := m.Submit(Submission{Partner: "THEM", Filename: "order.edi", Payload: []byte("ISA*~")})
	if err != nil {
		t.Fatal(err)
	}
	j := waitFor(t, m, job.ID, Delivered, Failed)
	if j.State != Delivered || j.Attempts != 3 {
		t.Fatalf("state %s after %d attempts: %s", j.State, j.Attempts, j.LastError)
	}
	if !strings.HasSuffix(j.Disposition, "; processed") {
		t.Errorf("disposition %q", j.Disposition)
	}
	if got, err := os.ReadFile(filepath.Join(j.ArchiveDir, "payload", "order.edi")); err != nil || string(got) != "ISA*~" {
		t.Errorf("archived payload %q, %v", got, err)
	}
	time.Sleep(50 * time.Millisecond) // the spool copy is removed just after the state changes
	if _, err := os.Stat(filepath.Join(m.dir(j.ID), "payload")); !os.IsNotExist(err) {
		t.Error("delivered payload left in the spool")
	}
}

func TestGiveUpThenManualRetry(t *testing.T) {
	us, them := newStation(t, "US"), newStation(t, "THEM")
	ps := newPartner(t, us, them)
	ps.fail.Store(3) // exactly MaxAttempts
	m := newManager(t, us, them, ps.URL, fullSecurity)

	job, _ := m.Submit(Submission{Partner: "THEM", Filename: "a.txt", Payload: []byte("hello")})
	j := waitFor(t, m, job.ID, Failed, Delivered)
	if j.State != Failed || !strings.Contains(j.LastError, "giving up after 3 attempts") {
		t.Fatalf("state %s: %s", j.State, j.LastError)
	}
	firstID := j.MessageID

	if _, err := m.Retry(job.ID); err != nil {
		t.Fatal(err)
	}
	j = waitFor(t, m, job.ID, Delivered, Failed)
	if j.State != Delivered {
		t.Fatalf("retry ended %s: %s", j.State, j.LastError)
	}
	if j.MessageID == firstID {
		t.Error("manual retry reused the old Message-ID")
	}
}

func TestPartnerReportsError(t *testing.T) {
	us, them := newStation(t, "US"), newStation(t, "THEM")
	ps := newPartner(t, us, them)
	ps.rcv.Partners["US"].RequireEncryption = true
	opts := fullSecurity
	opts.Encrypt = false
	m := newManager(t, us, them, ps.URL, opts)

	job, _ := m.Submit(Submission{Partner: "THEM", Filename: "a.txt", Payload: []byte("hello")})
	j := waitFor(t, m, job.ID, Failed, Delivered)
	if j.State != Failed || !strings.Contains(j.LastError, "insufficient-message-security") || j.Attempts != 1 {
		t.Fatalf("state %s after %d attempts: %s", j.State, j.Attempts, j.LastError)
	}
}

func TestAsyncMDN(t *testing.T) {
	us, them := newStation(t, "US"), newStation(t, "THEM")
	ps := newPartner(t, us, them)
	opts := fullSecurity
	opts.AsyncMDNURL = "http://us.example/as2"
	m := newManager(t, us, them, ps.URL, opts)

	job, _ := m.Submit(Submission{Partner: "THEM", Filename: "a.txt", Payload: []byte("hello")})
	waitFor(t, m, job.ID, AwaitingMDN)
	mdn := <-ps.async

	// An MDN from someone else, or for another message, is refused.
	forged := mdn.Header.Clone()
	forged.Set("AS2-From", "MALLORY")
	if err := m.HandleMDN(forged, mdn.Body); err == nil {
		t.Error("MDN from an unknown partner was accepted")
	}

	if err := m.HandleMDN(mdn.Header, mdn.Body); err != nil {
		t.Fatal(err)
	}
	if j := waitFor(t, m, job.ID, Delivered, Failed); j.State != Delivered {
		t.Fatalf("state %s: %s", j.State, j.LastError)
	}
}

// TestAsyncMDNBeforeResponse covers partners that post the async MDN before
// answering the message POST, while the job is still in a worker's hands.
func TestAsyncMDNBeforeResponse(t *testing.T) {
	us, them := newStation(t, "US"), newStation(t, "THEM")
	ps := newPartner(t, us, them)
	opts := fullSecurity
	opts.AsyncMDNURL = "http://us.example/as2"
	m := newManager(t, us, them, ps.URL, opts)
	ps.early = func(mdn *as2.MDN) {
		if err := m.HandleMDN(mdn.Header, mdn.Body); err != nil {
			t.Error(err)
		}
	}

	job, _ := m.Submit(Submission{Partner: "THEM", Filename: "a.txt", Payload: []byte("hello")})
	if j := waitFor(t, m, job.ID, Delivered, Failed); j.State != Delivered || j.Attempts != 1 {
		t.Fatalf("state %s after %d attempts: %s", j.State, j.Attempts, j.LastError)
	}
}

func TestSpoolSurvivesRestart(t *testing.T) {
	us, them := newStation(t, "US"), newStation(t, "THEM")
	spool := t.TempDir()
	cfg := Config{
		Local:       us,
		Partners:    map[string]*Partner{"THEM": {Partner: &as2.Partner{ID: "THEM", Cert: them.Cert}, URL: "http://unused", Options: fullSecurity}},
		SpoolDir:    spool,
		Archive:     &archive.Store{Root: t.TempDir()},
		Log:         slog.New(slog.DiscardHandler),
		MaxAttempts: 3,
	}
	m1, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	job, _ := m1.Submit(Submission{Partner: "THEM", Filename: "a.txt", Payload: []byte("hello")})

	m2, err := New(cfg) // a restarted daemon
	if err != nil {
		t.Fatal(err)
	}
	j, ok := m2.Get(job.ID)
	if !ok || j.State != Pending || j.Filename != "a.txt" {
		t.Fatalf("after restart: %+v, %v", j, ok)
	}
}
