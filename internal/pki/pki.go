// Package pki loads certificates and private keys from PEM files.
package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadCertificate reads the first certificate in a PEM file.
func LoadCertificate(path string) (*x509.Certificate, error) {
	block, err := readPEM(path, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cert, nil
}

// LoadPrivateKey reads a PKCS#8, PKCS#1 or SEC 1 private key from a PEM file.
func LoadPrivateKey(path string) (crypto.Signer, error) {
	block, err := readPEM(path, "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: unsupported key type %T", path, key)
	}
	return signer, nil
}

// CheckKeyPair reports whether key is the private half of cert.
func CheckKeyPair(cert *x509.Certificate, key crypto.Signer) error {
	pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(key.Public()) {
		return errors.New("private key does not match certificate")
	}
	return nil
}

func readPEM(path string, types ...string) (*pem.Block, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s: no %s PEM block found", path, types[0])
		}
		for _, t := range types {
			if block.Type == t {
				return block, nil
			}
		}
	}
}
