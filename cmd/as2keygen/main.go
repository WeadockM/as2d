// Command as2keygen creates a self-signed RSA certificate and key for an AS2
// station. Partners exchange certificates out of band, so self-signed
// certificates are normal in AS2.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/WeadockM/as2d/internal/version"
)

func main() {
	id := flag.String("id", "", "AS2 ID, used as the certificate's common name (required)")
	out := flag.String("out", ".", "directory to write <id>.crt and <id>.key to")
	bits := flag.Int("bits", 3072, "RSA key size")
	days := flag.Int("days", 730, "validity period in days")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("as2keygen", version.String())
		return
	}
	if *id == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*id, *out, *bits, *days); err != nil {
		fmt.Fprintln(os.Stderr, "as2keygen:", err)
		os.Exit(1)
	}
}

func run(id, out string, bits, days int) error {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: id},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	certPath := filepath.Join(out, id+".crt")
	keyPath := filepath.Join(out, id+".key")
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s\n", certPath, keyPath)
	return nil
}

func writePEM(path, typ string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
