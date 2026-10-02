package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"

	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
)

const payload = "ISA*00*          *00*          *ZZ*PARTNER        *ZZ*LOCAL          ~"

// payloadEntity is the MIME entity the partner signs; its digest is the MIC.
const payloadEntity = "Content-Type: application/edi-x12\r\n" +
	"Content-Disposition: attachment; filename=\"po.edi\"\r\n\r\n" + payload

type identity struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newIdentity(t *testing.T, cn string) identity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return identity{cert, key}
}

type fixture struct {
	srv     *Server
	local   identity
	partner identity
	root    string
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{local: newIdentity(t, "LOCAL"), partner: newIdentity(t, "PARTNER"), root: t.TempDir()}
	rcv := &as2.Receiver{
		Local: as2.Station{ID: "LOCAL", Cert: f.local.cert, Key: f.local.key},
		Partners: map[string]*as2.Partner{
			"PARTNER": {ID: "PARTNER", Cert: f.partner.cert, RequireSignature: true},
		},
	}
	f.srv = New(rcv, &archive.Store{Root: f.root}, slog.New(slog.DiscardHandler), 1<<20)
	f.srv.RetryDelays = []time.Duration{0}
	return f
}

// sign wraps entity in multipart/signed, as the partner's AS2 software would.
func (f *fixture) sign(t *testing.T, entity string) (contentType, body string) {
	t.Helper()
	sd, err := pkcs7.NewSignedData([]byte(entity))
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(f.partner.cert, f.partner.key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.Detach()
	sig, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	body = "--sig\r\n" + entity + "\r\n--sig\r\n" +
		"Content-Type: application/pkcs7-signature; name=smime.p7s\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(sig) + "\r\n--sig--\r\n"
	return `multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="sig"`, body
}

func (f *fixture) encrypt(t *testing.T, contentType, body string) []byte {
	t.Helper()
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
	der, err := pkcs7.Encrypt([]byte("Content-Type: "+contentType+"\r\n\r\n"+body), []*x509.Certificate{f.local.cert})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (f *fixture) post(contentType string, body []byte, extra map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/as2", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("AS2-Version", "1.2")
	req.Header.Set("AS2-From", "PARTNER")
	req.Header.Set("AS2-To", "LOCAL")
	req.Header.Set("Message-ID", fmt.Sprintf("<test-%d@partner>", time.Now().UnixNano()))
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	return rec
}

// archived returns the single archived message directory.
func (f *fixture) archived(t *testing.T) string {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join(f.root, "inbound", "PARTNER", "*", "*", "*", "*"))
	if len(dirs) != 1 {
		t.Fatalf("want 1 archived message, found %d", len(dirs))
	}
	return dirs[0]
}

var signedMDN = map[string]string{
	"Disposition-Notification-To":      "mailto:as2@partner.example",
	"Disposition-Notification-Options": "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha-256, sha1",
}

var unsignedMDN = map[string]string{"Disposition-Notification-To": "mailto:as2@partner.example"}

func TestSignedEncryptedMessage(t *testing.T) {
	f := newFixture(t)
	ct, body := f.sign(t, payloadEntity)
	rec := f.post("application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m", f.encrypt(t, ct, body), signedMDN)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	report, err := as2.VerifySigned(rec.Header().Get("Content-Type"), rec.Body.Bytes(), f.local.cert)
	if err != nil {
		t.Fatalf("MDN signature: %v", err)
	}
	sum := sha256.Sum256([]byte(payloadEntity))
	for _, want := range []string{
		"Disposition: automatic-action/MDN-sent-automatically; processed\r\n",
		"Received-Content-MIC: " + base64.StdEncoding.EncodeToString(sum[:]) + ", sha-256\r\n",
	} {
		if !strings.Contains(string(report), want) {
			t.Errorf("MDN is missing %q:\n%s", want, report)
		}
	}
	if got := rec.Header().Get("AS2-To"); got != "PARTNER" {
		t.Errorf("MDN AS2-To = %q", got)
	}

	dir := f.archived(t)
	got, err := os.ReadFile(filepath.Join(dir, "payload", "po.edi"))
	if err != nil || string(got) != payload {
		t.Errorf("archived payload = %q, %v", got, err)
	}
	for _, name := range []string{"request.http", "mdn.http", "meta.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Error(err)
		}
	}
}

func TestFailures(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T, *fixture) (string, []byte)
		want  string
	}{
		{
			name: "tampered content",
			build: func(t *testing.T, f *fixture) (string, []byte) {
				ct, body := f.sign(t, payloadEntity)
				return ct, []byte(strings.Replace(body, "PARTNER ", "MALLORY ", 1))
			},
			want: as2.ModIntegrityCheckFailed,
		},
		{
			name: "signed by someone else",
			build: func(t *testing.T, f *fixture) (string, []byte) {
				f.partner = newIdentity(t, "PARTNER")
				ct, body := f.sign(t, payloadEntity)
				return ct, []byte(body)
			},
			want: as2.ModAuthenticationFailed,
		},
		{
			name: "unsigned when a signature is required",
			build: func(t *testing.T, f *fixture) (string, []byte) {
				return "application/edi-x12", []byte(payload)
			},
			want: as2.ModInsufficientSecurity,
		},
		{
			name: "encrypted to another key",
			build: func(t *testing.T, f *fixture) (string, []byte) {
				f.local = newIdentity(t, "LOCAL")
				ct, body := f.sign(t, payloadEntity)
				return "application/pkcs7-mime; smime-type=enveloped-data", f.encrypt(t, ct, body)
			},
			want: as2.ModDecryptionFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			ct, body := tt.build(t, f)
			rec := f.post(ct, body, unsignedMDN)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			want := "processed/error: " + tt.want + "\r\n"
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("MDN is missing %q:\n%s", want, rec.Body)
			}
			if _, err := os.Stat(filepath.Join(f.archived(t), "payload")); !os.IsNotExist(err) {
				t.Error("payload of a failed message was archived")
			}
		})
	}
}

func TestUnknownPartner(t *testing.T) {
	f := newFixture(t)
	rec := f.post("application/edi-x12", []byte(payload), map[string]string{"AS2-From": "STRANGER"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", rec.Code)
	}
}

func TestNoMDNRequested(t *testing.T) {
	f := newFixture(t)
	ct, body := f.sign(t, payloadEntity)
	rec := f.post(ct, []byte(body), nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("status %d, body %q; want 200 with empty body", rec.Code, rec.Body)
	}
	f.archived(t)
}

func TestDuplicateAndInbox(t *testing.T) {
	f := newFixture(t)
	f.srv.InboxDir = t.TempDir()
	ct, body := f.sign(t, payloadEntity)
	headers := map[string]string{"Message-ID": "<dup-1@partner>"}
	for k, v := range unsignedMDN {
		headers[k] = v
	}

	if rec := f.post(ct, []byte(body), headers); !strings.Contains(rec.Body.String(), "; processed\r\n") {
		t.Fatalf("first copy: %s", rec.Body)
	}
	got, err := os.ReadFile(filepath.Join(f.srv.InboxDir, "PARTNER", "po.edi"))
	if err != nil || string(got) != payload {
		t.Fatalf("inbox: %q, %v", got, err)
	}

	rec := f.post(ct, []byte(body), headers)
	if !strings.Contains(rec.Body.String(), "processed/warning: duplicate-document\r\n") {
		t.Errorf("second copy MDN:\n%s", rec.Body)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.srv.InboxDir, "PARTNER")); len(entries) != 1 {
		t.Errorf("inbox has %d files after a duplicate, want 1", len(entries))
	}
}

func TestCompressedMessage(t *testing.T) {
	f := newFixture(t)
	partner := as2.Station{ID: "PARTNER", Cert: f.partner.cert, Key: f.partner.key}
	out, err := partner.Package(&as2.Partner{ID: "LOCAL", Cert: f.local.cert}, []byte(payload), as2.SendOptions{
		Sign: true, Encrypt: true, Compress: as2.CompressBeforeSign, RequestMDN: true, SignedMDN: true,
		ContentType: "application/edi-x12", Filename: "po.edi",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/as2", bytes.NewReader(out.Body))
	req.Header = out.Header
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)

	rc, err := as2.ParseMDN(&as2.Partner{ID: "LOCAL", Cert: f.local.cert}, rec.Header(), rec.Body.Bytes())
	if err == nil {
		err = rc.Match(out.Sent)
	}
	if err != nil || !rc.Processed || !rc.MICMatches {
		t.Fatalf("receipt %+v, %v", rc, err)
	}
	meta, _ := os.ReadFile(filepath.Join(f.archived(t), "meta.json"))
	if !strings.Contains(string(meta), `"compressed": true`) {
		t.Errorf("meta.json does not record compression:\n%s", meta)
	}
}

type mdnSink struct{ got chan http.Header }

func (s mdnSink) HandleMDN(h http.Header, body []byte) error { s.got <- h; return nil }

func TestInboundMDNIsRouted(t *testing.T) {
	f := newFixture(t)
	sink := mdnSink{make(chan http.Header, 1)}
	f.srv.MDNs = sink
	report := "--r\r\nContent-Type: message/disposition-notification\r\n\r\nDisposition: automatic-action/MDN-sent-automatically; processed\r\n\r\n--r--\r\n"
	rec := f.post(`multipart/report; report-type=disposition-notification; boundary="r"`, []byte(report), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	select {
	case <-sink.got:
	default:
		t.Fatal("MDN was not handed to the outbound queue")
	}
}

func TestAsyncMDN(t *testing.T) {
	f := newFixture(t)
	got := make(chan []byte, 1)
	partner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- body
	}))
	defer partner.Close()

	ct, body := f.sign(t, payloadEntity)
	headers := map[string]string{"Receipt-Delivery-Option": partner.URL}
	for k, v := range signedMDN {
		headers[k] = v
	}
	rec := f.post(ct, []byte(body), headers)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("status %d, body %q; want 200 with empty body", rec.Code, rec.Body)
	}
	select {
	case mdn := <-got:
		if !strings.Contains(string(mdn), "; processed\r\n") {
			t.Errorf("async MDN does not report success:\n%s", mdn)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("async MDN was not delivered")
	}
	if err := f.srv.Shutdown(t.Context()); err != nil {
		t.Error(err)
	}
}
