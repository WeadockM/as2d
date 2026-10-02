package as2

import (
	"bytes"
	"compress/zlib"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
)

// CMS compressed-data (RFC 3274) with zlib, as used by AS2 (RFC 5402).

var (
	oidCompressedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 9}
	oidZlib           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 8}
	oidData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

// maxDecompressed bounds decompression so a small message cannot expand
// into an unbounded amount of memory.
const maxDecompressed = 1 << 30

type compressedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     compressedData `asn1:"explicit,tag:0"`
}

type compressedData struct {
	Version   int
	Algorithm pkix.AlgorithmIdentifier
	Encap     encapsulatedContent
}

type encapsulatedContent struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"explicit,tag:0"`
}

func compress(data []byte) ([]byte, error) {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(data)
	if err := w.Close(); err != nil {
		return nil, err
	}
	return asn1.Marshal(compressedContentInfo{
		ContentType: oidCompressedData,
		Content: compressedData{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidZlib},
			Encap:     encapsulatedContent{ContentType: oidData, Content: z.Bytes()},
		},
	})
}

// decompress accepts BER as well as DER, since streaming encoders commonly
// produce indefinite lengths and chunked OCTET STRINGs.
func decompress(ber []byte) ([]byte, error) {
	root, _, err := parseBER(ber, 0)
	if err != nil {
		return nil, fmt.Errorf("compressed-data: %w", err)
	}
	// ContentInfo { contentType, [0] { CompressedData { version, algorithm, encap { type, [0] { OCTET STRING } } } } }
	if len(root.children) < 2 || !root.children[0].isOID(oidCompressedData) {
		return nil, errors.New("compressed-data: not a CMS compressed-data structure")
	}
	cd := root.children[1].child(0)
	if cd == nil || len(cd.children) < 3 {
		return nil, errors.New("compressed-data: malformed CompressedData")
	}
	if alg := cd.children[1].child(0); alg == nil || !alg.isOID(oidZlib) {
		return nil, errors.New("compressed-data: unsupported compression algorithm")
	}
	encap := cd.children[2]
	if len(encap.children) < 2 {
		return nil, errors.New("compressed-data: no content")
	}
	octets := encap.children[1].child(0)
	if octets == nil {
		return nil, errors.New("compressed-data: no content")
	}
	r, err := zlib.NewReader(bytes.NewReader(octets.octets()))
	if err != nil {
		return nil, fmt.Errorf("compressed-data: %w", err)
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxDecompressed+1))
	if err != nil {
		return nil, fmt.Errorf("compressed-data: %w", err)
	}
	if len(out) > maxDecompressed {
		return nil, errors.New("compressed-data: decompressed content too large")
	}
	return out, nil
}

// berNode is one BER element. Constructed elements have children;
// primitive ones have content.
type berNode struct {
	tag         byte // first identifier octet: class, constructed bit and tag number
	constructed bool
	content     []byte
	children    []*berNode
}

func (n *berNode) child(i int) *berNode {
	if i < len(n.children) {
		return n.children[i]
	}
	return nil
}

func (n *berNode) isOID(oid asn1.ObjectIdentifier) bool {
	der, _ := asn1.Marshal(oid)
	return n.tag == 0x06 && bytes.Equal(n.content, der[2:])
}

// octets returns an OCTET STRING's value, joining the chunks of a
// constructed one.
func (n *berNode) octets() []byte {
	if !n.constructed {
		return n.content
	}
	var b []byte
	for _, c := range n.children {
		b = append(b, c.octets()...)
	}
	return b
}

// parseBER parses one element starting at b[0] and returns it with the
// number of bytes consumed.
func parseBER(b []byte, depth int) (*berNode, int, error) {
	if depth > 32 {
		return nil, 0, errors.New("BER nested too deeply")
	}
	if len(b) < 2 {
		return nil, 0, errors.New("truncated BER element")
	}
	n := &berNode{tag: b[0], constructed: b[0]&0x20 != 0}
	if b[0]&0x1f == 0x1f {
		return nil, 0, errors.New("multi-byte BER tags are not supported")
	}
	pos := 2
	length := int(b[1])
	indefinite := false
	switch {
	case b[1] == 0x80:
		if !n.constructed {
			return nil, 0, errors.New("indefinite length on a primitive BER element")
		}
		indefinite = true
	case b[1] > 0x80:
		k := int(b[1] & 0x7f)
		if k > 4 || len(b) < 2+k {
			return nil, 0, errors.New("bad BER length")
		}
		length = 0
		for _, c := range b[2 : 2+k] {
			length = length<<8 | int(c)
		}
		pos += k
	}

	if indefinite {
		for {
			if len(b) < pos+2 {
				return nil, 0, errors.New("unterminated indefinite-length BER element")
			}
			if b[pos] == 0 && b[pos+1] == 0 {
				return n, pos + 2, nil
			}
			c, used, err := parseBER(b[pos:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			n.children = append(n.children, c)
			pos += used
		}
	}

	if length < 0 || len(b)-pos < length {
		return nil, 0, errors.New("BER length exceeds data")
	}
	n.content = b[pos : pos+length]
	if n.constructed {
		for off := 0; off < length; {
			c, used, err := parseBER(n.content[off:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			n.children = append(n.children, c)
			off += used
		}
	}
	return n, pos + length, nil
}
