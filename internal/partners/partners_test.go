package partners

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/config"
	"github.com/WeadockM/as2d/internal/outbound"
)

func certPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type fixture struct {
	rt       *Runtime
	receiver *as2.Receiver
	mgr      *outbound.Manager
	dir      string
}

// newFixture has one config.json partner, CONFIGCO, and dashboard editing.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	cfgCert := filepath.Join(dir, "configco.crt")
	os.WriteFile(cfgCert, certPEM(t, "CONFIGCO"), 0o600)
	store, err := OpenStore(filepath.Join(dir, "state", "partners"))
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := outbound.New(outbound.Config{SpoolDir: filepath.Join(dir, "spool"),
		Archive: &archive.Store{Root: dir}, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{receiver: &as2.Receiver{}, mgr: mgr, dir: dir}
	f.rt = &Runtime{
		Sys:   &config.Config{Local: config.Station{AS2ID: "US"}, PublicURL: "https://us.example/as2"},
		Store: store, Receiver: f.receiver, Manager: mgr, Log: slog.New(slog.DiscardHandler),
	}
	cfgPartners := []config.Partner{{AS2ID: "CONFIGCO", Cert: cfgCert,
		Outbound: &config.Outbound{URL: "https://configco.example/as2"}}}
	if err := f.rt.Load(cfgPartners); err != nil {
		t.Fatal(err)
	}
	return f
}

func outboundTo(url string) *config.Outbound { return &config.Outbound{URL: url, Cipher: "aes128-gcm"} }

func TestSaveAppliesLive(t *testing.T) {
	f := newFixture(t)
	if _, ok := f.receiver.Partner("NEWCO"); ok {
		t.Fatal("NEWCO known before it was added")
	}
	rec, err := f.rt.Save(Record{AS2ID: "NEWCO", RequireSignature: true, Outbound: outboundTo("https://newco.example/as2")},
		certPEM(t, "NEWCO"), "alice", "created")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != 1 || rec.UpdatedBy != "alice" || rec.Action != "created" {
		t.Errorf("record = %+v", rec)
	}
	// The receiver and the queue see the new partner at once.
	p, ok := f.receiver.Partner("NEWCO")
	if !ok || !p.RequireSignature {
		t.Fatalf("receiver partner = %+v, %v", p, ok)
	}
	if _, err := f.mgr.Submit(outbound.Submission{Partner: "NEWCO", Payload: []byte("x")}); err != nil {
		t.Errorf("queue doesn't know the new partner: %v", err)
	}
	e, _ := f.rt.Current().Entry("NEWCO")
	if e.Source != FromDashboard || e.Record.Version != 1 {
		t.Errorf("entry = %+v", e)
	}
	// config.json partners are still there.
	if _, ok := f.receiver.Partner("CONFIGCO"); !ok {
		t.Error("config partner lost")
	}
}

func TestInvalidChangesAreRefused(t *testing.T) {
	f := newFixture(t)
	for name, tc := range map[string]struct {
		rec  Record
		cert []byte
		want string
	}{
		"bad url":        {Record{AS2ID: "BAD", Outbound: outboundTo("ftp://x")}, certPEM(t, "BAD"), "http:// or https://"},
		"bad cipher":     {Record{AS2ID: "BAD", Outbound: &config.Outbound{URL: "https://x.example", Cipher: "rot13"}}, certPEM(t, "BAD"), "unknown cipher"},
		"local id":       {Record{AS2ID: "US"}, certPEM(t, "US"), "local station"},
		"bad id":         {Record{AS2ID: `quote"d`}, certPEM(t, "Q"), "printable ASCII"},
		"not a cert":     {Record{AS2ID: "BAD"}, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), "certificate"},
		"async, no url":  {Record{AS2ID: "BAD", Outbound: &config.Outbound{URL: "https://x.example", MDN: "async"}}, certPEM(t, "BAD"), ""},
		"forward secret": {Record{AS2ID: "BAD", Forward: &config.Forward{URL: "https://boomi", Username: "u", PasswordFile: "/nope", Mode: "queued"}}, certPEM(t, "BAD"), "forward"},
	} {
		if name == "async, no url" {
			f.rt.Sys.PublicURL = ""
		}
		_, err := f.rt.Save(tc.rec, tc.cert, "alice", "created")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
		f.rt.Sys.PublicURL = "https://us.example/as2"
		if _, _, err := f.rt.Store.Get(tc.rec.AS2ID); err == nil {
			t.Errorf("%s: invalid partner was written", name)
		}
	}
}

func TestHistoryRestoreAndDelete(t *testing.T) {
	f := newFixture(t)
	certA, certB := certPEM(t, "A"), certPEM(t, "B")
	f.rt.Save(Record{AS2ID: "ACME", Outbound: outboundTo("https://one.example/as2")}, certA, "alice", "created")
	f.rt.Save(Record{AS2ID: "ACME", Outbound: outboundTo("https://two.example/as2")}, nil, "bob", "updated")
	f.rt.Save(Record{AS2ID: "ACME", Outbound: outboundTo("https://two.example/as2")}, certB, "bob", "updated")

	if got := f.mgrURL(t, "ACME"); got != "https://two.example/as2" {
		t.Errorf("URL in effect = %s", got)
	}
	hist, err := f.rt.Store.History("ACME")
	if err != nil || len(hist) != 3 || hist[0].Version != 3 || hist[2].UpdatedBy != "alice" {
		t.Fatalf("history = %+v, %v", hist, err)
	}
	// Version 2 kept certificate A, from version 1.
	if _, c, _ := f.rt.Store.Version("ACME", 2); string(c) != string(certA) {
		t.Error("version 2 lost its certificate")
	}

	rec, err := f.rt.Restore("ACME", 1, "carol")
	if err != nil || rec.Version != 4 || rec.Action != "restored version 1" {
		t.Fatalf("restore = %+v, %v", rec, err)
	}
	if got := f.mgrURL(t, "ACME"); got != "https://one.example/as2" {
		t.Errorf("URL after restore = %s", got)
	}
	if _, c, _ := f.rt.Store.Get("ACME"); string(c) != string(certA) {
		t.Error("restore did not bring back the certificate")
	}

	// A partner with a queued message can't be deleted.
	f.mgr.Submit(outbound.Submission{Partner: "ACME", Payload: []byte("x")})
	if err := f.rt.Delete("ACME", "carol"); err != ErrPending {
		t.Fatalf("delete with a queued message: %v", err)
	}
	f2 := newFixture(t)
	f2.rt.Save(Record{AS2ID: "GONE"}, certPEM(t, "GONE"), "alice", "created")
	if err := f2.rt.Delete("GONE", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f2.receiver.Partner("GONE"); ok {
		t.Error("deleted partner still receives")
	}
	hist, _ = f2.rt.Store.History("GONE")
	if len(hist) != 2 || hist[0].Action != "deleted" {
		t.Errorf("history after delete = %+v", hist)
	}
	if _, err := f2.rt.Restore("GONE", 1, "alice"); err != nil {
		t.Errorf("restoring a deleted partner: %v", err)
	}
}

func (f *fixture) mgrURL(t *testing.T, id string) string {
	t.Helper()
	for _, e := range f.rt.Current().Entries {
		if e.Config.AS2ID == id && e.Config.Outbound != nil {
			return e.Config.Outbound.URL
		}
	}
	return ""
}

func TestImportFromConfig(t *testing.T) {
	f := newFixture(t)
	rec, err := f.rt.Import("CONFIGCO", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Action != "imported from config.json" || rec.Outbound == nil || rec.Outbound.URL != "https://configco.example/as2" {
		t.Errorf("imported = %+v", rec)
	}
	e, _ := f.rt.Current().Entry("CONFIGCO")
	if e.Source != FromDashboard || !e.AlsoInConfig {
		t.Errorf("after import: source %s, also in config %v", e.Source, e.AlsoInConfig)
	}
	if _, err := f.rt.Import("CONFIGCO", "alice"); err == nil {
		t.Error("imported twice")
	}
	// Deleting the dashboard copy hands the partner back to config.json.
	if err := f.rt.Delete("CONFIGCO", "alice"); err != nil {
		t.Fatal(err)
	}
	if e, ok := f.rt.Current().Entry("CONFIGCO"); !ok || e.Source != FromConfig {
		t.Errorf("after deleting the dashboard copy: %+v, %v", e, ok)
	}
}

func TestSendingNeedsAQueue(t *testing.T) {
	f := newFixture(t)
	f.rt.Manager = nil
	_, err := f.rt.Save(Record{AS2ID: "NEWCO", Outbound: outboundTo("https://newco.example/as2")}, certPEM(t, "NEWCO"), "alice", "created")
	if err == nil || !strings.Contains(err.Error(), "spool_dir") {
		t.Errorf("err = %v", err)
	}
}

func TestParseCertificateFormats(t *testing.T) {
	pemData := certPEM(t, "X")
	block, _ := pem.Decode(pemData)
	for name, input := range map[string]string{
		"pem":         string(pemData),
		"base64 der":  base64Wrap(block.Bytes),
		"pem with ws": "\n\n  " + string(pemData) + "\n",
	} {
		c, out, err := ParseCertificate(input)
		if err != nil || c.Subject.CommonName != "X" || string(out) != string(pemData) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := ParseCertificate("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Errorf("private key accepted as a certificate: %v", err)
	}
}

func base64Wrap(b []byte) string {
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "X", Bytes: b}))[len("-----BEGIN X-----\n") : len(pem.EncodeToMemory(&pem.Block{Type: "X", Bytes: b}))-len("-----END X-----\n")])
}
