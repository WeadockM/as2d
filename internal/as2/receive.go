// Package as2 implements the AS2 protocol (RFC 4130): unwrapping inbound
// messages and producing message disposition notifications (MDNs).
package as2

import (
	"bytes"
	"crypto"
	_ "crypto/sha1" // register hashes used for MICs
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/smallstep/pkcs7"
)

// Disposition modifiers from RFC 4130 section 7.4.3.
const (
	ModAuthenticationFailed      = "authentication-failed"
	ModDecompressionFailed       = "decompression-failed" // RFC 5402
	ModDecryptionFailed          = "decryption-failed"
	ModInsufficientSecurity      = "insufficient-message-security"
	ModIntegrityCheckFailed      = "integrity-check-failed"
	ModUnexpectedProcessingError = "unexpected-processing-error"
)

// Errors returned by Process for requests that are rejected outright, with
// no MDN, because the sender or recipient cannot be identified.
var (
	ErrMissingHeaders   = errors.New("as2: missing AS2-From, AS2-To or Message-ID header")
	ErrUnknownRecipient = errors.New("as2: AS2-To does not match the local station")
	ErrUnknownPartner   = errors.New("as2: AS2-From is not a configured partner")
)

// Station is the local AS2 identity: the certificate partners encrypt to and
// the key used to decrypt messages and sign MDNs.
type Station struct {
	ID   string
	Cert *x509.Certificate
	Key  crypto.PrivateKey
}

// Partner is a remote trading partner.
type Partner struct {
	ID                string
	Cert              *x509.Certificate // verifies the partner's signatures
	RequireEncryption bool
	RequireSignature  bool
}

// Receiver unwraps inbound AS2 messages addressed to Local.
type Receiver struct {
	Local    Station
	Partners map[string]*Partner // keyed by AS2 ID
}

// Failure records why a message could not be processed. It is reported to
// the partner in the MDN as "processed/error: <Modifier>".
type Failure struct {
	Modifier string
	Err      error
}

func (f *Failure) Error() string { return f.Modifier + ": " + f.Err.Error() }
func (f *Failure) Unwrap() error { return f.Err }

func fail(modifier string, err error) *Failure { return &Failure{Modifier: modifier, Err: err} }

// ReceiptRequest is what the sender asked for in the way of an MDN.
type ReceiptRequest struct {
	To       string   // Disposition-Notification-To
	Signed   bool     // a signed MDN was requested
	MICAlgs  []string // signed-receipt-micalg values, most preferred first
	AsyncURL string   // Receipt-Delivery-Option; empty for a synchronous MDN
}

// Message is the outcome of processing one inbound AS2 request.
type Message struct {
	ID      string // Message-ID header, angle brackets included
	From    string
	To      string
	Subject string
	Partner *Partner
	Receipt *ReceiptRequest // nil when no MDN was requested

	Encrypted   bool
	Signed      bool
	Compressed  bool
	ContentType string // of the payload
	Filename    string // from the payload's Content-Disposition, if any
	Payload     []byte

	MIC     string // base64 digest returned in Received-Content-MIC
	MICAlg  string // algorithm label as the sender spelled it, e.g. "sha-256"
	micHash crypto.Hash

	Failure *Failure // nil when the message was processed successfully
	Warning string   // e.g. WarnDuplicateDocument; reported as processed/warning
}

// WarnDuplicateDocument is reported when a Message-ID was already processed.
const WarnDuplicateDocument = "duplicate-document"

// Process unwraps an inbound AS2 request. A non-nil error means the request
// was rejected without an MDN. Otherwise the returned Message describes the
// result, and Message.Failure says whether processing succeeded.
func (r *Receiver) Process(h http.Header, body []byte) (*Message, error) {
	msg := &Message{
		ID:      strings.TrimSpace(h.Get("Message-Id")),
		From:    UnquoteID(h.Get("As2-From")),
		To:      UnquoteID(h.Get("As2-To")),
		Subject: h.Get("Subject"),
		Receipt: parseReceiptRequest(h),
	}
	if msg.ID == "" || msg.From == "" || msg.To == "" {
		return nil, ErrMissingHeaders
	}
	if msg.To != r.Local.ID {
		return nil, fmt.Errorf("%w: %q", ErrUnknownRecipient, msg.To)
	}
	partner, ok := r.Partners[msg.From]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPartner, msg.From)
	}
	msg.Partner = partner
	msg.Failure = r.unwrap(msg, h, body)
	return msg, nil
}

// unwrap removes the encryption, signature and compression layers, in
// whatever order the sender applied them, then extracts the payload.
func (r *Receiver) unwrap(msg *Message, h http.Header, body []byte) *Failure {
	ent := httpEntity(h, body)
	// The MIC covers the signed content if there is a signature, otherwise
	// the innermost (decrypted, uncompressed) entity (RFC 5402 section 3).
	micInput := ent.raw
	micDefault := ""

layers:
	for {
		mt, params, err := ent.mediaType()
		if err != nil {
			return fail(ModUnexpectedProcessingError, err)
		}
		var inner []byte
		switch {
		case isPKCS7Mime(mt) && !msg.Compressed && isSMIMEType(params, "compressed-data"):
			if inner, err = decompress(mustDecode(ent)); err != nil {
				return fail(ModDecompressionFailed, err)
			}
			msg.Compressed = true

		case isPKCS7Mime(mt) && !msg.Encrypted && isSMIMEType(params, "enveloped-data", ""):
			if inner, err = r.decrypt(ent); err != nil {
				return fail(ModDecryptionFailed, err)
			}
			msg.Encrypted = true

		case isPKCS7Mime(mt):
			return fail(ModUnexpectedProcessingError, fmt.Errorf("unsupported or repeated smime-type %q", params["smime-type"]))

		case mt == "multipart/signed" && !msg.Signed:
			if inner, err = verifySigned(ent.body, params["boundary"], msg.Partner.Cert); err != nil {
				if _, ok := errors.AsType[*pkcs7.MessageDigestMismatchError](err); ok {
					return fail(ModIntegrityCheckFailed, err)
				}
				return fail(ModAuthenticationFailed, err)
			}
			msg.Signed = true
			micInput = inner
			micDefault = params["micalg"]

		default:
			break layers
		}
		if ent, err = parseEntity(inner); err != nil {
			return fail(ModUnexpectedProcessingError, err)
		}
		if !msg.Signed {
			micInput = ent.raw
		}
	}

	msg.MICAlg, msg.micHash = chooseMICAlg(msg.Receipt, micDefault)
	sum := msg.micHash.New()
	sum.Write(micInput)
	msg.MIC = base64.StdEncoding.EncodeToString(sum.Sum(nil))

	if msg.Partner.RequireEncryption && !msg.Encrypted {
		return fail(ModInsufficientSecurity, errors.New("partner requires encrypted messages"))
	}
	if msg.Partner.RequireSignature && !msg.Signed {
		return fail(ModInsufficientSecurity, errors.New("partner requires signed messages"))
	}

	var err error
	if msg.Payload, err = ent.decodedBody(); err != nil {
		return fail(ModUnexpectedProcessingError, fmt.Errorf("decode payload: %w", err))
	}
	msg.ContentType = ent.header.Get("Content-Type")
	if cd := ent.header.Get("Content-Disposition"); cd != "" {
		if _, p, err := mime.ParseMediaType(cd); err == nil {
			msg.Filename = p["filename"]
		}
	}
	return nil
}

func (r *Receiver) decrypt(e *entity) ([]byte, error) {
	der := mustDecode(e)
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("parse enveloped data: %w", err)
	}
	return p7.Decrypt(r.Local.Cert, r.Local.Key)
}

// mustDecode returns the DER inside an application/pkcs7-mime entity. It
// tolerates senders that base64-encode the body without saying so.
func mustDecode(e *entity) []byte {
	der, err := e.decodedBody()
	if err != nil {
		return e.body
	}
	if len(der) > 0 && der[0] != 0x30 { // not an ASN.1 SEQUENCE
		if alt, err := decodeBase64(der); err == nil {
			return alt
		}
	}
	return der
}

func isPKCS7Mime(mt string) bool {
	return mt == "application/pkcs7-mime" || mt == "application/x-pkcs7-mime"
}

func isSMIMEType(params map[string]string, types ...string) bool {
	return slices.Contains(types, strings.ToLower(params["smime-type"]))
}

// IsMDN reports whether an inbound request carries an MDN (typically an
// asynchronous one) rather than a message: a multipart/report, possibly
// inside multipart/signed.
func IsMDN(h http.Header, body []byte) bool {
	ent := httpEntity(h, body)
	mt, params, err := ent.mediaType()
	if err != nil {
		return false
	}
	if mt == "multipart/report" {
		return true
	}
	if mt != "multipart/signed" {
		return false
	}
	parts, err := splitMultipart(ent.body, params["boundary"])
	if err != nil || len(parts) == 0 {
		return false
	}
	first, err := parseEntity(parts[0])
	if err != nil {
		return false
	}
	mt, _, _ = first.mediaType()
	return mt == "multipart/report"
}

// VerifySigned checks a multipart/signed entity, given its Content-Type and
// body, against cert and returns the signed part exactly as it was signed.
func VerifySigned(contentType string, body []byte, cert *x509.Certificate) ([]byte, error) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, err
	}
	if mt != "multipart/signed" {
		return nil, fmt.Errorf("as2: content type is %s, not multipart/signed", mt)
	}
	return verifySigned(body, params["boundary"], cert)
}

func verifySigned(body []byte, boundary string, cert *x509.Certificate) ([]byte, error) {
	parts, err := splitMultipart(body, boundary)
	if err != nil {
		return nil, err
	}
	if len(parts) != 2 {
		return nil, fmt.Errorf("multipart/signed has %d parts, want 2", len(parts))
	}
	sigEnt, err := parseEntity(parts[1])
	if err != nil {
		return nil, fmt.Errorf("signature part: %w", err)
	}
	sig, err := sigEnt.decodedBody()
	if err != nil {
		return nil, fmt.Errorf("signature part: %w", err)
	}
	content := parts[0]
	err = verifyDetached(content, sig, cert)
	if err == nil {
		return content, nil
	}
	// Some senders sign the canonical CRLF form but transmit bare LFs.
	if canon := toCRLF(content); !bytes.Equal(canon, content) && verifyDetached(canon, sig, cert) == nil {
		return canon, nil
	}
	return nil, err
}

func verifyDetached(content, sig []byte, cert *x509.Certificate) error {
	p7, err := pkcs7.Parse(sig)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}
	p7.Content = content
	// Senders may leave their certificate out of the signature, and the
	// configured partner certificate is the only one trusted anyway, so it
	// goes first in the lookup list.
	p7.Certificates = append([]*x509.Certificate{cert}, p7.Certificates...)
	if signer := p7.GetOnlySigner(); signer == nil || !signer.Equal(cert) {
		return errors.New("message was not signed with the partner's certificate")
	}
	return p7.Verify()
}

// parseReceiptRequest reads the MDN request headers, e.g.
//
//	Disposition-Notification-Options: signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha256, sha1
func parseReceiptRequest(h http.Header) *ReceiptRequest {
	to := h.Get("Disposition-Notification-To")
	if to == "" {
		return nil
	}
	rr := &ReceiptRequest{To: to, AsyncURL: strings.TrimSpace(h.Get("Receipt-Delivery-Option"))}
	for _, param := range strings.Split(h.Get("Disposition-Notification-Options"), ";") {
		name, value, ok := strings.Cut(param, "=")
		if !ok {
			continue
		}
		var vals []string
		for _, v := range strings.Split(value, ",")[1:] { // the first value is the importance
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
				vals = append(vals, v)
			}
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "signed-receipt-protocol":
			rr.Signed = slices.Contains(vals, "pkcs7-signature")
		case "signed-receipt-micalg":
			rr.MICAlgs = vals
		}
	}
	return rr
}

var micHashes = map[string]crypto.Hash{
	"sha1": crypto.SHA1, "sha-1": crypto.SHA1,
	"sha256": crypto.SHA256, "sha-256": crypto.SHA256,
	"sha384": crypto.SHA384, "sha-384": crypto.SHA384,
	"sha512": crypto.SHA512, "sha-512": crypto.SHA512,
}

// chooseMICAlg picks the first supported algorithm the sender asked for,
// then the signature's micalg, then SHA-256.
func chooseMICAlg(rr *ReceiptRequest, fallback string) (string, crypto.Hash) {
	var requested []string
	if rr != nil {
		requested = rr.MICAlgs
	}
	for _, name := range slices.Concat(requested, []string{strings.ToLower(fallback), "sha-256"}) {
		if h, ok := micHashes[name]; ok {
			return name, h
		}
	}
	panic("unreachable")
}

// UnquoteID strips the optional quoting around an AS2 identifier.
func UnquoteID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var b strings.Builder
		for i := 1; i < len(s)-1; i++ {
			if s[i] == '\\' && i+1 < len(s)-1 {
				i++
			}
			b.WriteByte(s[i])
		}
		return b.String()
	}
	return s
}

// quoteID quotes an AS2 identifier when it contains characters that are not
// allowed in a bare token.
func quoteID(s string) string {
	if !strings.ContainsAny(s, " \t\"\\()<>@,;:/[]?=") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
