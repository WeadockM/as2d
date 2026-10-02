package outbound

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WeadockM/as2d/internal/forward"
)

// submit posts a payload to the API and decodes the job it returns.
func submit(t *testing.T, api *httptest.Server, query, correlationID string) (int, http.Header, Job) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, api.URL+"/api/messages?"+query, strings.NewReader("ISA*00*~"))
	req.Header.Set("Authorization", "Bearer tok")
	if correlationID != "" {
		req.Header.Set("X-Correlation-ID", correlationID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var j Job
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, j
}

func newAPI(t *testing.T, m *Manager) *httptest.Server {
	s := httptest.NewServer(m.APIHandler("tok", 1<<20))
	t.Cleanup(s.Close)
	return s
}

func TestSubmitWaitDelivered(t *testing.T) {
	us, them := newStation(t, "US"), newStation(t, "THEM")
	ps := newPartner(t, us, them)
	api := newAPI(t, newManager(t, us, them, ps.URL, fullSecurity))

	status, header, j := submit(t, api, "partner=THEM&filename=po.edi&wait=10s", "boomi-doc-42")
	if status != http.StatusOK || j.State != Delivered {
		t.Fatalf("status %d, job %+v", status, j)
	}
	if !strings.HasSuffix(j.Disposition, "; processed") || j.MIC == "" || j.MDNMessageID == "" {
		t.Errorf("MDN result missing: disposition %q, mic %q, mdn %q", j.Disposition, j.MIC, j.MDNMessageID)
	}
	if j.CorrelationID != "boomi-doc-42" || header.Get("X-Correlation-ID") != "boomi-doc-42" {
		t.Errorf("correlation ID: job %q, header %q", j.CorrelationID, header.Get("X-Correlation-ID"))
	}
}

func TestSubmitWaitFailed(t *testing.T) {
	us, them := newStation(t, "US"), newStation(t, "THEM")
	ps := newPartner(t, us, them)
	ps.rcv.Partners["US"].RequireEncryption = true
	opts := fullSecurity
	opts.Encrypt = false
	api := newAPI(t, newManager(t, us, them, ps.URL, opts))

	status, _, j := submit(t, api, "partner=THEM&filename=po.edi&wait=10s", "")
	if status != http.StatusOK || j.State != Failed || !strings.Contains(j.Disposition, "insufficient-message-security") {
		t.Fatalf("status %d, state %s, disposition %q", status, j.State, j.Disposition)
	}
}

func TestSubmitWaitTimesOut(t *testing.T) {
	us, them := newStation(t, "US"), newStation(t, "THEM")
	ps := newPartner(t, us, them) // holds async MDNs instead of sending them
	opts := fullSecurity
	opts.AsyncMDNURL = "http://us.example/as2"
	api := newAPI(t, newManager(t, us, them, ps.URL, opts))

	start := time.Now()
	status, _, j := submit(t, api, "partner=THEM&filename=po.edi&wait=300ms", "")
	if status != http.StatusAccepted || j.State != AwaitingMDN {
		t.Fatalf("status %d, state %s", status, j.State)
	}
	if d := time.Since(start); d < 300*time.Millisecond || d > 5*time.Second {
		t.Errorf("returned after %v", d)
	}
}

func TestSubmitWithoutWaitAndAuth(t *testing.T) {
	us, them := newStation(t, "US"), newStation(t, "THEM")
	ps := newPartner(t, us, them)
	api := newAPI(t, newManager(t, us, them, ps.URL, fullSecurity))

	if status, _, j := submit(t, api, "partner=THEM&filename=po.edi", ""); status != http.StatusAccepted || j.State != Pending {
		t.Errorf("status %d, state %s", status, j.State)
	}
	resp, err := http.Post(api.URL+"/api/messages?partner=THEM", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: status %d", resp.StatusCode)
	}
}

func TestStatusWebhook(t *testing.T) {
	var (
		mu       sync.Mutex
		received []Job
		auth     []string
		calls    atomic.Int32
	)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "try again", http.StatusBadGateway) // first callback fails once
			return
		}
		var j Job
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &j); err != nil {
			t.Error(err)
		}
		mu.Lock()
		received = append(received, j)
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer hook.Close()

	us, them := newStation(t, "US"), newStation(t, "THEM")
	ps := newPartner(t, us, them)
	m := newManager(t, us, them, ps.URL, fullSecurity, func(c *Config) {
		c.Webhook = &forward.Webhook{URL: hook.URL, BearerToken: "hook-token", Client: http.DefaultClient}
		c.WebhookDelays = []time.Duration{0, 20 * time.Millisecond, 20 * time.Millisecond}
	})

	ok, _ := m.Submit(Submission{Partner: "THEM", Filename: "a.edi", CorrelationID: "doc-ok", Payload: []byte("x")})
	if j := waitFor(t, m, ok.ID, Delivered, Failed); j.State != Delivered {
		t.Fatalf("first message %s: %s", j.State, j.LastError)
	}
	ps.fail.Store(ps.requests.Load() + 3) // the next 3 attempts (all of them) fail
	bad, _ := m.Submit(Submission{Partner: "THEM", Filename: "b.edi", CorrelationID: "doc-bad", Payload: []byte("y")})
	if j := waitFor(t, m, bad.ID, Delivered, Failed); j.State != Failed {
		t.Fatalf("second message %s", j.State)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		a, _ := m.Get(ok.ID)
		b, _ := m.Get(bad.ID)
		if a.Notified && b.Notified {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	got := map[string]State{}
	for _, j := range received {
		got[j.CorrelationID] = j.State
	}
	if got["doc-ok"] != Delivered || got["doc-bad"] != Failed || len(received) != 2 {
		t.Errorf("callbacks: %v (%d received)", got, len(received))
	}
	for _, a := range auth {
		if a != "Bearer hook-token" {
			t.Errorf("Authorization = %q", a)
		}
	}
}
