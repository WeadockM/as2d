package as2

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/http"
	"net/textproto"
	"strings"
)

// entity is a MIME entity together with the exact bytes it was parsed from.
// Signatures and MICs are computed over those bytes, so an entity is never
// re-serialized.
type entity struct {
	raw    []byte
	header textproto.MIMEHeader
	body   []byte
}

func parseEntity(raw []byte) (*entity, error) {
	hdrLen, bodyStart := findHeaderEnd(raw)
	if hdrLen < 0 {
		return nil, errors.New("mime: missing blank line after headers")
	}
	e := &entity{raw: raw, header: textproto.MIMEHeader{}, body: raw[bodyStart:]}
	if hdrLen > 0 {
		hdr := make([]byte, 0, hdrLen+4)
		hdr = append(hdr, raw[:hdrLen]...)
		hdr = append(hdr, "\r\n\r\n"...)
		h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(hdr))).ReadMIMEHeader()
		if err != nil {
			return nil, fmt.Errorf("mime: parse headers: %w", err)
		}
		e.header = h
	}
	return e, nil
}

// httpEntity rebuilds the MIME entity carried by an HTTP request. AS2 puts
// the entity's MIME headers in the HTTP header block.
func httpEntity(h http.Header, body []byte) *entity {
	hdr := textproto.MIMEHeader{}
	var raw bytes.Buffer
	for _, k := range []string{"Content-Type", "Content-Transfer-Encoding", "Content-Disposition"} {
		if v := h.Get(k); v != "" {
			hdr.Set(k, v)
			fmt.Fprintf(&raw, "%s: %s\r\n", k, v)
		}
	}
	raw.WriteString("\r\n")
	raw.Write(body)
	return &entity{raw: raw.Bytes(), header: hdr, body: body}
}

// findHeaderEnd returns the length of the header block and the offset at
// which the body starts. Both CRLF and bare LF line endings are accepted.
func findHeaderEnd(raw []byte) (hdrLen, bodyStart int) {
	switch {
	case bytes.HasPrefix(raw, []byte("\r\n")):
		return 0, 2
	case bytes.HasPrefix(raw, []byte("\n")):
		return 0, 1
	}
	hdrLen, bodyStart = -1, -1
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		hdrLen, bodyStart = i, i+4
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 && (hdrLen < 0 || i < hdrLen) {
		hdrLen, bodyStart = i, i+2
	}
	return hdrLen, bodyStart
}

func (e *entity) mediaType() (string, map[string]string, error) {
	ct := e.header.Get("Content-Type")
	if ct == "" {
		return "text/plain", map[string]string{}, nil
	}
	return mime.ParseMediaType(ct)
}

// decodedBody returns the body with its Content-Transfer-Encoding removed.
func (e *entity) decodedBody() ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(e.header.Get("Content-Transfer-Encoding"))) {
	case "base64":
		return decodeBase64(e.body)
	case "quoted-printable":
		return io.ReadAll(quotedprintable.NewReader(bytes.NewReader(e.body)))
	default:
		return e.body, nil
	}
}

// decodeBase64 decodes base64 text that may be wrapped across lines.
func decodeBase64(b []byte) ([]byte, error) {
	clean := bytes.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', ' ', '\t':
			return -1
		}
		return r
	}, b)
	return base64.StdEncoding.DecodeString(string(clean))
}

// wrapBase64 encodes b as base64 in 76-character CRLF-terminated lines.
func wrapBase64(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var out bytes.Buffer
	for len(enc) > 76 {
		out.WriteString(enc[:76])
		out.WriteString("\r\n")
		enc = enc[76:]
	}
	out.WriteString(enc)
	return out.Bytes()
}

// splitMultipart returns the raw bytes of each body part exactly as they
// appear between the boundary delimiters (RFC 2046 section 5.1.1).
func splitMultipart(body []byte, boundary string) ([][]byte, error) {
	if boundary == "" {
		return nil, errors.New("mime: multipart entity has no boundary")
	}
	delim := []byte("--" + boundary)
	var parts [][]byte
	start := -1 // offset where the current part's content begins
	for pos := 0; pos < len(body); {
		i := bytes.Index(body[pos:], delim)
		if i < 0 {
			break
		}
		i += pos
		pos = i + len(delim)
		if i > 0 && body[i-1] != '\n' {
			continue // boundary text in the middle of a line
		}
		if pos < len(body) && !strings.ContainsRune("-\r\n \t", rune(body[pos])) {
			continue // a longer boundary that merely starts with ours
		}
		if start >= 0 {
			// The line break before a delimiter belongs to the delimiter.
			end := i
			if end > start && body[end-1] == '\n' {
				end--
			}
			if end > start && body[end-1] == '\r' {
				end--
			}
			parts = append(parts, body[start:end])
		}
		if bytes.HasPrefix(body[pos:], []byte("--")) {
			return parts, nil
		}
		nl := bytes.IndexByte(body[pos:], '\n')
		if nl < 0 {
			break
		}
		pos += nl + 1
		start = pos
	}
	return nil, errors.New("mime: multipart entity has no closing delimiter")
}

// toCRLF converts bare LF line endings to CRLF.
func toCRLF(b []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(b) + len(b)/32)
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			out.WriteByte('\r')
		}
		out.WriteByte(c)
	}
	return out.Bytes()
}
