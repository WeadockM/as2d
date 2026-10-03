package web

import (
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/WeadockM/as2d/internal/accounts"
	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/config"
	"github.com/WeadockM/as2d/internal/index"
	"github.com/WeadockM/as2d/internal/outbound"
	"github.com/WeadockM/as2d/internal/partners"
)

func certText(t *testing.T, cn string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert(t, cn, time.Now().AddDate(1, 0, 0)).Raw}))
}

// newPartnerSite is a dashboard with accounts, an editable partner store,
// a queue, and one config.json partner, OLDCO.
func newPartnerSite(t *testing.T) (*usersSite, *partners.Runtime, *as2.Receiver) {
	t.Helper()
	dir := t.TempDir()
	pepper := filepath.Join(dir, "pepper.key")
	os.WriteFile(pepper, []byte(accounts.GeneratePepper()), 0o600)
	peppers, _ := accounts.LoadPeppers(pepper, nil)
	st, _ := accounts.Open(filepath.Join(dir, "state.db"))
	t.Cleanup(func() { st.Close() })
	svc := accounts.NewService(st, peppers)
	temps := map[string]string{}
	for name, role := range map[string]accounts.Role{"alice": accounts.Admin, "vic": accounts.Viewer} {
		temps[name], _ = svc.CreateUser("cli", name, role, "")
	}

	db, _, _ := index.Open(filepath.Join(dir, "as2d.db"), dir)
	t.Cleanup(func() { db.Close() })
	mgr, err := outbound.New(outbound.Config{SpoolDir: filepath.Join(dir, "spool"),
		Archive: &archive.Store{Root: dir}, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	store, _ := partners.OpenStore(filepath.Join(dir, "partners"))
	receiver := &as2.Receiver{}
	oldCert := filepath.Join(dir, "oldco.crt")
	os.WriteFile(oldCert, []byte(certText(t, "OLDCO")), 0o600)
	rt := &partners.Runtime{Sys: &config.Config{Local: config.Station{AS2ID: "US"}}, Store: store,
		Receiver: receiver, Manager: mgr, Log: slog.New(slog.DiscardHandler)}
	if err := rt.Load([]config.Partner{{AS2ID: "OLDCO", Cert: oldCert, RequireSignature: true}}); err != nil {
		t.Fatal(err)
	}

	h := Handler(Config{Index: db, Queue: mgr, Accounts: svc, Partners: rt,
		Local: as2.Station{ID: "US", Cert: cert(t, "US", time.Now().AddDate(1, 0, 0))},
		Log:   slog.New(slog.DiscardHandler)})
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return &usersSite{s, svc, temps}, rt, receiver
}

func jsonBody(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestPartnerEditing(t *testing.T) {
	s, rt, receiver := newPartnerSite(t)
	admin, viewer := s.signIn(t, "alice"), s.signIn(t, "vic")

	newco := map[string]any{
		"as2_id": "NEWCO", "require_signature": true, "certificate": certText(t, "NEWCO"),
		"outbound": map[string]any{"url": "https://newco.example/as2", "encrypt": true, "sign": true,
			"signed_mdn": true, "cipher": "aes256-gcm", "micalg": "sha-256", "compress": "none", "mdn": "sync"},
	}
	if code, _ := viewer.do("POST", "/api/partners", jsonBody(newco)); code != http.StatusForbidden {
		t.Errorf("viewer creating a partner: %d", code)
	}
	code, body := admin.do("POST", "/api/partners", jsonBody(newco))
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, body)
	}
	if p, ok := receiver.Partner("NEWCO"); !ok || !p.RequireSignature {
		t.Fatal("new partner not live")
	}

	// Invalid changes are refused with a clear error, and nothing changes.
	bad := map[string]any{"as2_id": "BADCO", "certificate": "not a certificate"}
	if code, body := admin.do("POST", "/api/partners", jsonBody(bad)); code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "certificate") {
		t.Errorf("bad certificate: %d %v", code, body)
	}
	bad = map[string]any{"as2_id": "BADCO", "certificate": certText(t, "BADCO"), "outbound": map[string]any{"url": "nope"}}
	if code, body := admin.do("POST", "/api/partners", jsonBody(bad)); code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "url") {
		t.Errorf("bad url: %d %v", code, body)
	}
	if code, _ := admin.do("POST", "/api/partners", jsonBody(newco)); code != http.StatusConflict {
		t.Errorf("duplicate: %d", code)
	}
	if code, body := admin.do("POST", "/api/partners", jsonBody(map[string]any{"as2_id": "OLDCO", "certificate": certText(t, "X")})); code != http.StatusConflict ||
		!strings.Contains(body["error"].(string), "import") {
		t.Errorf("creating over a config partner: %d %v", code, body)
	}

	// Update: stop requiring signatures and switch to async MDNs... which
	// need a public URL, so set one for this partner.
	upd := map[string]any{"require_signature": false,
		"outbound": map[string]any{"url": "https://newco.example/as2", "encrypt": true, "sign": true, "signed_mdn": true,
			"cipher": "aes256-gcm", "micalg": "sha-256", "compress": "none", "mdn": "async", "async_mdn_url": "https://us.example/as2"}}
	if code, body := admin.do("PUT", "/api/partners/NEWCO", jsonBody(upd)); code != http.StatusOK {
		t.Fatalf("update: %d %v", code, body)
	}
	if p, _ := receiver.Partner("NEWCO"); p.RequireSignature {
		t.Error("update not live")
	}

	// History has both versions; restoring version 1 brings the old settings back.
	req, _ := http.NewRequest("GET", s.URL+"/api/partners/NEWCO/history", nil)
	resp, _ := admin.http.Do(req)
	var hist []map[string]any
	json.NewDecoder(resp.Body).Decode(&hist)
	resp.Body.Close()
	if len(hist) != 2 || hist[0]["updated_by"] != "alice" {
		t.Fatalf("history = %v", hist)
	}
	if sum := hist[0]["summary"].(string); !strings.Contains(sum, "mdn: sync → async") || !strings.Contains(sum, "require_signature: false") {
		t.Errorf("history summary = %q", sum)
	}
	if code, _ := admin.do("POST", "/api/partners/NEWCO/history/1/restore", ""); code != http.StatusOK {
		t.Fatalf("restore: %d", code)
	}
	if p, _ := receiver.Partner("NEWCO"); !p.RequireSignature {
		t.Error("restore not live")
	}

	// Import the config.json partner, then delete NEWCO.
	if code, body := admin.do("POST", "/api/partners/OLDCO/import", ""); code != http.StatusOK || body["partner"].(map[string]any)["source"] != "dashboard" {
		t.Errorf("import: %d %v", code, body)
	}
	if code, _ := admin.do("DELETE", "/api/partners/NEWCO", ""); code != http.StatusNoContent {
		t.Errorf("delete: %d", code)
	}
	if _, ok := receiver.Partner("NEWCO"); ok {
		t.Error("deleted partner still live")
	}
	if len(rt.Current().Entries) != 1 {
		t.Errorf("partners now: %d", len(rt.Current().Entries))
	}

	// Every change is in the audit log, with what changed.
	_, audit := admin.do("GET", "/api/audit?limit=100", "")
	var actions []string
	var updateDetails map[string]any
	for _, e := range audit["entries"].([]any) {
		entry := e.(map[string]any)
		actions = append(actions, entry["action"].(string))
		if entry["action"] == "partner_update" {
			updateDetails, _ = entry["details"].(map[string]any)
		}
	}
	joined := strings.Join(actions, ",")
	for _, want := range []string{"partner_create", "partner_update", "partner_restore", "partner_import", "partner_delete"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit lacks %s: %s", want, joined)
		}
	}
	if updateDetails["require_signature"] != false || updateDetails["outbound.mdn"] != "sync → async" {
		t.Errorf("update details = %v", updateDetails)
	}
}

func TestCertificateInspect(t *testing.T) {
	s, _, _ := newPartnerSite(t)
	admin := s.signIn(t, "alice")
	code, body := admin.do("POST", "/api/certificates/inspect", jsonBody(map[string]string{"certificate": certText(t, "PEEK")}))
	if code != http.StatusOK || !strings.Contains(body["subject"].(string), "PEEK") || len(body["sha256"].(string)) != 64 {
		t.Errorf("inspect: %d %v", code, body)
	}
}
