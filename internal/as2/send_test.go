package as2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func newStation(t *testing.T, id string) Station {
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Station{ID: id, Cert: cert, Key: key}
}

// TestRoundTrip sends from one station to another's Receiver and checks the
// MDN, for every combination of signing and encryption.
func TestRoundTrip(t *testing.T) {
	sender, receiver := newStation(t, "Sender Co"), newStation(t, "RECEIVER")
	rcv := &Receiver{Local: receiver, Partners: map[string]*Partner{
		"Sender Co": {ID: "Sender Co", Cert: sender.Cert},
	}}
	toReceiver := &Partner{ID: "RECEIVER", Cert: receiver.Cert}
	payload := []byte("UNB+UNOC:3+SENDER+RECEIVER'\nline two with a bare LF\n")

	var cases []SendOptions
	for _, sign := range []bool{false, true} {
		for _, encrypt := range []bool{false, true} {
			cases = append(cases, SendOptions{Sign: sign, Encrypt: encrypt, SignedMDN: sign})
		}
	}
	for c := range Ciphers {
		cases = append(cases, SendOptions{Sign: true, Encrypt: true, Cipher: c})
	}
	for _, alg := range []string{"sha-1", "sha-384", "sha-512"} {
		cases = append(cases, SendOptions{Sign: true, Encrypt: true, SignedMDN: true, MICAlg: alg})
	}
	for _, mode := range []string{CompressBeforeSign, CompressAfterSign} {
		for _, sign := range []bool{false, true} {
			for _, encrypt := range []bool{false, true} {
				cases = append(cases, SendOptions{Sign: sign, Encrypt: encrypt, SignedMDN: sign, Compress: mode})
			}
		}
	}

	for _, opts := range cases {
		name := fmt.Sprintf("sign=%v encrypt=%v compress=%s cipher=%s micalg=%s",
			opts.Sign, opts.Encrypt, opts.Compress, opts.Cipher, opts.MICAlg)
		t.Run(name, func(t *testing.T) {
			opts.RequestMDN = true
			opts.ContentType = "application/edifact"
			opts.Filename = "orders.edi"
			out, err := sender.Package(toReceiver, payload, opts)
			if err != nil {
				t.Fatal(err)
			}

			msg, err := rcv.Process(out.Header, out.Body)
			if err != nil {
				t.Fatal(err)
			}
			if msg.Failure != nil {
				t.Fatalf("receiver failed: %v", msg.Failure)
			}
			if string(msg.Payload) != string(payload) || msg.Filename != "orders.edi" {
				t.Errorf("received %q as %q", msg.Payload, msg.Filename)
			}
			if msg.Signed != opts.Sign || msg.Encrypted != opts.Encrypt || msg.Compressed != (opts.Compress != "") {
				t.Errorf("signed=%v encrypted=%v compressed=%v", msg.Signed, msg.Encrypted, msg.Compressed)
			}

			mdn, err := rcv.BuildMDN(msg)
			if err != nil {
				t.Fatal(err)
			}
			rc, err := ParseMDN(toReceiver, mdn.Header, mdn.Body)
			if err == nil {
				err = rc.Match(out.Sent)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !rc.Processed || !rc.MICMatches || rc.Signed != opts.SignedMDN {
				t.Errorf("receipt: %+v (sender MICs %v)", rc, out.MICs)
			}
		})
	}
}

func TestReadMDNReportsFailure(t *testing.T) {
	sender, receiver := newStation(t, "S"), newStation(t, "R")
	rcv := &Receiver{Local: receiver, Partners: map[string]*Partner{
		"S": {ID: "S", Cert: sender.Cert, RequireEncryption: true},
	}}
	out, err := sender.Package(&Partner{ID: "R", Cert: receiver.Cert}, []byte("x"),
		SendOptions{Sign: true, RequestMDN: true, SignedMDN: true})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := rcv.Process(out.Header, out.Body)
	if err != nil {
		t.Fatal(err)
	}
	mdn, err := rcv.BuildMDN(msg)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := ParseMDN(&Partner{ID: "R", Cert: receiver.Cert}, mdn.Header, mdn.Body)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Processed || rc.Modifier != "error: "+ModInsufficientSecurity {
		t.Errorf("receipt: %+v", rc)
	}

	// An MDN signed by someone other than the partner must be rejected.
	if _, err := ParseMDN(&Partner{ID: "R", Cert: sender.Cert}, mdn.Header, mdn.Body); err == nil {
		t.Error("MDN signed by the wrong key was accepted")
	}
}
