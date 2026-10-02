package as2

import (
	"bytes"
	"testing"
)

func TestCompressRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("ISA*00*compressible*~\r\n"), 500)
	der, err := compress(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(der) >= len(data) {
		t.Errorf("compressed %d bytes to %d", len(data), len(der))
	}
	got, err := decompress(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("round trip changed the data")
	}
}

// TestDecompressBER checks the indefinite-length, chunked encoding that
// streaming encoders such as BouncyCastle produce.
func TestDecompressBER(t *testing.T) {
	der, err := compress([]byte("hello, BER"))
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := parseBER(der, 0)
	if err != nil {
		t.Fatal(err)
	}
	z := root.children[1].child(0).children[2].children[1].child(0).content

	oid := func(n *berNode) []byte { return append([]byte{0x06, byte(len(n.content))}, n.content...) }
	indef := func(tag byte, parts ...[]byte) []byte {
		b := []byte{tag, 0x80}
		for _, p := range parts {
			b = append(b, p...)
		}
		return append(b, 0, 0)
	}
	octets := indef(0x24, // constructed OCTET STRING in two chunks
		append([]byte{0x04, byte(len(z[:3]))}, z[:3]...),
		append([]byte{0x04, byte(len(z[3:]))}, z[3:]...))
	cd := root.children[1].child(0)
	alg := cd.children[1]
	ber := indef(0x30,
		oid(root.children[0]),
		indef(0xa0, indef(0x30,
			[]byte{0x02, 0x01, 0x00},
			append([]byte{0x30, byte(len(alg.content))}, alg.content...),
			indef(0x30, oid(cd.children[2].children[0]), indef(0xa0, octets)),
		)),
	)

	got, err := decompress(ber)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello, BER" {
		t.Errorf("got %q", got)
	}
}
