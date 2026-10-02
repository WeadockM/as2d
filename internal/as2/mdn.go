package as2

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"
)

// MDN is a message disposition notification ready to send. Header holds the
// HTTP headers, including Content-Type, and Body the HTTP body.
type MDN struct {
	MessageID string
	Header    http.Header
	Body      []byte
}

// Bytes serializes the MDN as headers, a blank line and the body.
func (m *MDN) Bytes() []byte {
	var b bytes.Buffer
	m.Header.Write(&b)
	b.WriteString("\r\n")
	b.Write(m.Body)
	return b.Bytes()
}

// Disposition returns the Disposition field reported for the message.
func (m *Message) Disposition() string {
	d := "automatic-action/MDN-sent-automatically; processed"
	switch {
	case m.Failure != nil:
		d += "/error: " + m.Failure.Modifier
	case m.Warning != "":
		d += "/warning: " + m.Warning
	}
	return d
}

var signingAlgs = map[crypto.Hash]struct {
	oid   asn1.ObjectIdentifier
	label string // micalg parameter, RFC 5751 section 3.4.3.2
}{
	crypto.SHA1:   {pkcs7.OIDDigestAlgorithmSHA1, "sha-1"},
	crypto.SHA256: {pkcs7.OIDDigestAlgorithmSHA256, "sha-256"},
	crypto.SHA384: {pkcs7.OIDDigestAlgorithmSHA384, "sha-384"},
	crypto.SHA512: {pkcs7.OIDDigestAlgorithmSHA512, "sha-512"},
}

// BuildMDN builds the MDN for msg, signed if the sender asked for that.
// msg.Receipt must not be nil.
func (r *Receiver) BuildMDN(msg *Message) (*MDN, error) {
	ct, body := buildReport(msg)
	if msg.Receipt.Signed {
		part := append([]byte("Content-Type: "+ct+"\r\n\r\n"), body...)
		var err error
		if ct, body, err = r.Local.sign(part, msg.micHash); err != nil {
			return nil, fmt.Errorf("as2: sign MDN: %w", err)
		}
	}
	m := &MDN{MessageID: newMessageID(r.Local.ID), Header: http.Header{}, Body: body}
	m.Header.Set("Content-Type", ct)
	m.Header.Set("MIME-Version", "1.0")
	m.Header.Set("AS2-Version", "1.2")
	m.Header.Set("AS2-From", quoteID(r.Local.ID))
	m.Header.Set("AS2-To", quoteID(msg.From))
	m.Header.Set("Message-ID", m.MessageID)
	m.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	return m, nil
}

// buildReport returns the multipart/report entity (RFC 3798) for msg.
func buildReport(msg *Message) (contentType string, body []byte) {
	boundary := newBoundary()
	text := fmt.Sprintf("The AS2 message %s from %s was received and processed successfully.", msg.ID, msg.From)
	switch {
	case msg.Failure != nil:
		text = fmt.Sprintf("The AS2 message %s from %s was received but could not be processed: %s.",
			msg.ID, msg.From, msg.Failure.Modifier)
	case msg.Warning == WarnDuplicateDocument:
		text = fmt.Sprintf("The AS2 message %s from %s was received again. It was already processed, so it was not delivered a second time.",
			msg.ID, msg.From)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\r\n%s\r\n", boundary, text)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: message/disposition-notification\r\nContent-Transfer-Encoding: 7bit\r\n\r\n", boundary)
	b.WriteString("Reporting-UA: as2d\r\n")
	fmt.Fprintf(&b, "Original-Recipient: rfc822; %s\r\n", msg.To)
	fmt.Fprintf(&b, "Final-Recipient: rfc822; %s\r\n", msg.To)
	fmt.Fprintf(&b, "Original-Message-ID: %s\r\n", msg.ID)
	if msg.MIC != "" && msg.Failure == nil {
		fmt.Fprintf(&b, "Received-Content-MIC: %s, %s\r\n", msg.MIC, msg.MICAlg)
	}
	fmt.Fprintf(&b, "Disposition: %s\r\n", msg.Disposition())
	fmt.Fprintf(&b, "\r\n--%s--\r\n", boundary)
	return fmt.Sprintf(`multipart/report; report-type=disposition-notification; boundary="%s"`, boundary), b.Bytes()
}

// sign wraps a MIME entity (headers and body) in multipart/signed with a
// detached PKCS#7 signature made with the station's key.
func (s Station) sign(part []byte, hash crypto.Hash) (string, []byte, error) {
	alg, ok := signingAlgs[hash]
	if !ok {
		alg = signingAlgs[crypto.SHA256]
	}
	sd, err := pkcs7.NewSignedData(part)
	if err != nil {
		return "", nil, err
	}
	sd.SetDigestAlgorithm(alg.oid)
	if err := sd.AddSigner(s.Cert, s.Key, pkcs7.SignerInfoConfig{}); err != nil {
		return "", nil, err
	}
	sd.Detach()
	sig, err := sd.Finish()
	if err != nil {
		return "", nil, err
	}

	boundary := newBoundary()
	var b bytes.Buffer
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.Write(part)
	fmt.Fprintf(&b, "\r\n--%s\r\n", boundary)
	b.WriteString("Content-Type: application/pkcs7-signature; name=smime.p7s\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("Content-Disposition: attachment; filename=smime.p7s\r\n\r\n")
	b.Write(wrapBase64(sig))
	fmt.Fprintf(&b, "\r\n--%s--\r\n", boundary)
	ct := fmt.Sprintf(`multipart/signed; protocol="application/pkcs7-signature"; micalg=%s; boundary="%s"`, alg.label, boundary)
	return ct, b.Bytes(), nil
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newBoundary() string { return "----=_as2d_" + randHex(12) }

func newMessageID(localID string) string {
	host := strings.Map(func(r rune) rune {
		if r < 0x80 && (r == '.' || r == '-' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return r
		}
		return '_'
	}, localID)
	return fmt.Sprintf("<%s.%s@%s>", time.Now().UTC().Format("20060102150405"), randHex(8), host)
}
