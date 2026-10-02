package config

import (
	"fmt"

	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/pki"
)

// Stations loads the local station's certificate and key and every
// partner's certificate.
func (c *Config) Stations() (as2.Station, map[string]*as2.Partner, error) {
	cert, err := pki.LoadCertificate(c.Local.Cert)
	if err != nil {
		return as2.Station{}, nil, err
	}
	key, err := pki.LoadPrivateKey(c.Local.Key)
	if err != nil {
		return as2.Station{}, nil, err
	}
	if err := pki.CheckKeyPair(cert, key); err != nil {
		return as2.Station{}, nil, fmt.Errorf("local station: %w", err)
	}
	partners := map[string]*as2.Partner{}
	for _, p := range c.Partners {
		pc, err := pki.LoadCertificate(p.Cert)
		if err != nil {
			return as2.Station{}, nil, fmt.Errorf("partner %q: %w", p.AS2ID, err)
		}
		partners[p.AS2ID] = &as2.Partner{
			ID:                p.AS2ID,
			Cert:              pc,
			RequireEncryption: p.RequireEncryption,
			RequireSignature:  p.RequireSignature,
		}
	}
	return as2.Station{ID: c.Local.AS2ID, Cert: cert, Key: key}, partners, nil
}
