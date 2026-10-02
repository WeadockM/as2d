package as2

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/smallstep/pkcs7"
)

// Ciphers maps the names accepted in SendOptions.Cipher to pkcs7 algorithms.
var Ciphers = map[string]int{
	"aes128-cbc": pkcs7.EncryptionAlgorithmAES128CBC,
	"aes256-cbc": pkcs7.EncryptionAlgorithmAES256CBC,
	"aes128-gcm": pkcs7.EncryptionAlgorithmAES128GCM,
	"aes256-gcm": pkcs7.EncryptionAlgorithmAES256GCM,
}

// Compression modes for SendOptions.Compress.
const (
	CompressNone       = ""
	CompressBeforeSign = "before-sign"
	CompressAfterSign  = "after-sign"
)

// pkcs7 selects the content cipher through a package variable, so
// encryption is serialized.
var encryptMu sync.Mutex

// SendOptions controls how an outbound message is packaged.
type SendOptions struct {
	Encrypt  bool
	Cipher   string // a key of Ciphers; default aes256-cbc
	Sign     bool
	MICAlg   string // sha-1, sha-256, sha-384 or sha-512; default sha-256
	Compress string // CompressNone, CompressBeforeSign or CompressAfterSign

	RequestMDN  bool
	SignedMDN   bool
	AsyncMDNURL string // empty for a synchronous MDN

	ContentType string // of the payload; default application/octet-stream
	Filename    string
	Subject     string
}

// Sent records what is needed to check the MDN for a message. It is
// JSON-encodable so a queue can persist it while waiting for an async MDN.
type Sent struct {
	MessageID string            `json:"message_id"`
	MICs      map[string]string `json:"mics"` // expected MIC by algorithm, e.g. "sha-256"
	SignedMDN bool              `json:"signed_mdn"`
}

// Outbound is a packaged message ready to POST to the partner.
type Outbound struct {
	Sent
	Header http.Header
	Body   []byte
}

// Bytes serializes the message as headers, a blank line and the body.
func (o *Outbound) Bytes() []byte {
	var b bytes.Buffer
	o.Header.Write(&b)
	b.WriteString("\r\n")
	b.Write(o.Body)
	return b.Bytes()
}

// part is a MIME entity under construction.
type part struct {
	header [][2]string
	body   []byte
}

func (p part) bytes() []byte {
	var b bytes.Buffer
	for _, h := range p.header {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	b.WriteString("\r\n")
	b.Write(p.body)
	return b.Bytes()
}

func pkcs7Part(smimeType, name string, der []byte) part {
	return part{[][2]string{
		{"Content-Type", fmt.Sprintf("application/pkcs7-mime; smime-type=%s; name=%s", smimeType, name)},
		{"Content-Transfer-Encoding", "binary"},
		{"Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name)},
	}, der}
}

// Package builds an AS2 message carrying payload from local to partner:
// compressed and signed with local's key as requested, then encrypted to
// partner.Cert.
func (local Station) Package(partner *Partner, payload []byte, opts SendOptions) (*Outbound, error) {
	if opts.ContentType == "" {
		opts.ContentType = "application/octet-stream"
	}
	if opts.MICAlg == "" {
		opts.MICAlg = "sha-256"
	}
	if opts.Cipher == "" {
		opts.Cipher = "aes256-cbc"
	}
	micHash, ok := micHashes[strings.ToLower(opts.MICAlg)]
	if !ok {
		return nil, fmt.Errorf("as2: unsupported MIC algorithm %q", opts.MICAlg)
	}
	cipher, ok := Ciphers[strings.ToLower(opts.Cipher)]
	if !ok {
		return nil, fmt.Errorf("as2: unsupported cipher %q", opts.Cipher)
	}
	switch opts.Compress {
	case CompressNone, CompressBeforeSign, CompressAfterSign:
	default:
		return nil, fmt.Errorf("as2: unsupported compression mode %q", opts.Compress)
	}

	// The innermost entity: the payload with its own MIME headers.
	cur := part{header: [][2]string{{"Content-Type", opts.ContentType}, {"Content-Transfer-Encoding", "binary"}}, body: payload}
	if opts.Filename != "" {
		cur.header = append(cur.header, [2]string{"Content-Disposition",
			mime.FormatMediaType("attachment", map[string]string{"filename": opts.Filename})})
	}
	// Unsigned messages' MIC covers the uncompressed payload entity; signed
	// messages' MIC covers whatever was signed (RFC 5402 section 3).
	micInput := cur.bytes()

	compressCur := func() error {
		der, err := compress(cur.bytes())
		if err != nil {
			return fmt.Errorf("as2: compress: %w", err)
		}
		cur = pkcs7Part("compressed-data", "smime.p7z", der)
		return nil
	}

	if opts.Compress == CompressBeforeSign {
		if err := compressCur(); err != nil {
			return nil, err
		}
	}
	if opts.Sign {
		micInput = cur.bytes()
		ct, body, err := local.sign(micInput, micHash)
		if err != nil {
			return nil, fmt.Errorf("as2: sign: %w", err)
		}
		cur = part{[][2]string{{"Content-Type", ct}}, body}
	}
	if opts.Compress == CompressAfterSign {
		if err := compressCur(); err != nil {
			return nil, err
		}
	}
	if opts.Encrypt {
		encryptMu.Lock()
		pkcs7.ContentEncryptionAlgorithm = cipher
		der, err := pkcs7.Encrypt(cur.bytes(), []*x509.Certificate{partner.Cert})
		encryptMu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("as2: encrypt: %w", err)
		}
		cur = pkcs7Part("enveloped-data", "smime.p7m", der)
	}

	h := http.Header{}
	for _, kv := range cur.header {
		h.Set(kv[0], kv[1])
	}
	out := &Outbound{
		Sent: Sent{
			MessageID: newMessageID(local.ID),
			MICs:      map[string]string{},
			SignedMDN: opts.RequestMDN && opts.SignedMDN,
		},
		Header: h,
		Body:   cur.body,
	}
	for hash, alg := range signingAlgs {
		out.MICs[alg.label] = digest(hash, micInput)
	}

	h.Set("MIME-Version", "1.0")
	h.Set("AS2-Version", "1.2")
	h.Set("AS2-From", quoteID(local.ID))
	h.Set("AS2-To", quoteID(partner.ID))
	h.Set("Message-ID", out.MessageID)
	h.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	if opts.Subject != "" {
		h.Set("Subject", opts.Subject)
	}
	if opts.RequestMDN {
		h.Set("Disposition-Notification-To", local.ID)
		if opts.SignedMDN {
			h.Set("Disposition-Notification-Options",
				"signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, "+opts.MICAlg)
		}
		if opts.AsyncMDNURL != "" {
			h.Set("Receipt-Delivery-Option", opts.AsyncMDNURL)
		}
	}
	return out, nil
}

func digest(h crypto.Hash, b []byte) string {
	sum := h.New()
	sum.Write(b)
	return base64.StdEncoding.EncodeToString(sum.Sum(nil))
}

// Receipt is a partner's MDN for an outbound message.
type Receipt struct {
	MessageID         string
	OriginalMessageID string
	Signed            bool
	Disposition       string
	Processed         bool   // processed with no error, failure or warning
	Modifier          string // e.g. "error: decryption-failed"
	MIC               string
	MICAlg            string
	MICMatches        bool // set by Match
	Text              string
}

// ParseMDN verifies (if signed) and parses an MDN received from partner.
func ParseMDN(partner *Partner, h http.Header, body []byte) (*Receipt, error) {
	rc := &Receipt{MessageID: strings.TrimSpace(h.Get("Message-Id"))}
	ent := httpEntity(h, body)
	mt, params, err := ent.mediaType()
	if err != nil {
		return nil, fmt.Errorf("as2: MDN: %w", err)
	}
	if mt == "multipart/signed" {
		signed, err := verifySigned(ent.body, params["boundary"], partner.Cert)
		if err != nil {
			return nil, fmt.Errorf("as2: MDN signature: %w", err)
		}
		if ent, err = parseEntity(signed); err != nil {
			return nil, fmt.Errorf("as2: MDN: %w", err)
		}
		rc.Signed = true
		if mt, params, err = ent.mediaType(); err != nil {
			return nil, fmt.Errorf("as2: MDN: %w", err)
		}
	}
	if mt != "multipart/report" {
		return nil, fmt.Errorf("as2: MDN has content type %s, want multipart/report", mt)
	}
	parts, err := splitMultipart(ent.body, params["boundary"])
	if err != nil {
		return nil, fmt.Errorf("as2: MDN: %w", err)
	}

	var fields textproto.MIMEHeader
	for _, p := range parts {
		pe, err := parseEntity(p)
		if err != nil {
			continue
		}
		switch pt, _, _ := pe.mediaType(); {
		case pt == "message/disposition-notification":
			if fields, err = parseFields(pe.body); err != nil {
				return nil, fmt.Errorf("as2: MDN fields: %w", err)
			}
		case pt == "text/plain" && rc.Text == "":
			rc.Text = strings.TrimSpace(string(pe.body))
		}
	}
	if fields == nil {
		return nil, errors.New("as2: MDN has no message/disposition-notification part")
	}

	rc.OriginalMessageID = strings.TrimSpace(fields.Get("Original-Message-Id"))
	rc.Disposition = strings.TrimSpace(fields.Get("Disposition"))
	if _, status, ok := strings.Cut(rc.Disposition, ";"); ok {
		status = strings.TrimSpace(status)
		if typ, mod, ok := strings.Cut(status, "/"); ok {
			rc.Modifier = strings.TrimSpace(mod)
			status = typ
		}
		rc.Processed = strings.EqualFold(strings.TrimSpace(status), "processed") && rc.Modifier == ""
	}
	if mic := fields.Get("Received-Content-Mic"); mic != "" {
		value, alg, _ := strings.Cut(mic, ",")
		rc.MIC, rc.MICAlg = strings.TrimSpace(value), strings.TrimSpace(alg)
	}
	return rc, nil
}

// Match checks that the receipt answers sent and records whether its MIC
// matches. An error means the receipt does not belong to sent or lacks a
// signature that was asked for.
func (rc *Receipt) Match(sent Sent) error {
	if rc.OriginalMessageID != "" && rc.OriginalMessageID != sent.MessageID {
		return fmt.Errorf("as2: MDN is for message %s, not %s", rc.OriginalMessageID, sent.MessageID)
	}
	if sent.SignedMDN && !rc.Signed {
		return errors.New("as2: a signed MDN was requested but the MDN is unsigned")
	}
	rc.MICMatches = false
	if hash, ok := micHashes[strings.ToLower(rc.MICAlg)]; ok && rc.MIC != "" {
		rc.MICMatches = rc.MIC == sent.MICs[signingAlgs[hash].label]
	}
	return nil
}

// parseFields parses a block of header-style fields that may lack the
// terminating blank line.
func parseFields(b []byte) (textproto.MIMEHeader, error) {
	b = append(bytes.TrimRight(b, "\r\n"), "\r\n\r\n"...)
	e, err := parseEntity(b)
	if err != nil {
		return nil, err
	}
	return e.header, nil
}
