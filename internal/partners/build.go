package partners

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/config"
	"github.com/WeadockM/as2d/internal/forward"
	"github.com/WeadockM/as2d/internal/outbound"
	"github.com/WeadockM/as2d/internal/server"
)

// Where a partner is defined.
const (
	FromConfig    = "config"
	FromDashboard = "dashboard"
)

// Entry is one partner in effect.
type Entry struct {
	Config       config.Partner
	Cert         *x509.Certificate
	Source       string  // FromConfig or FromDashboard
	AlsoInConfig bool    // a dashboard partner that config.json also defines
	Record       *Record // dashboard partners: version and who changed it
}

// Set is the partners in effect and everything built from them.
type Set struct {
	Entries  []Entry // by AS2 ID
	AS2      map[string]*as2.Partner
	Outbound map[string]*outbound.Partner
	Forwards map[string]*server.ForwardRule
	Queued   map[string]*forward.Target // forwards in queued mode
}

// Entry returns the partner with the given AS2 ID.
func (s *Set) Entry(id string) (Entry, bool) {
	for _, e := range s.Entries {
		if e.Config.AS2ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// build checks entries and builds a Set from them. canSend says whether
// there is an outbound queue, which sending and queued forwards need.
func build(sys *config.Config, entries []Entry, canSend bool) (*Set, error) {
	set := &Set{
		AS2:      map[string]*as2.Partner{},
		Outbound: map[string]*outbound.Partner{},
		Forwards: map[string]*server.ForwardRule{},
		Queued:   map[string]*forward.Target{},
	}
	var errs []error
	for _, e := range entries {
		p := e.Config
		fail := func(err error) { errs = append(errs, fmt.Errorf("partner %q: %w", p.AS2ID, err)) }
		if err := p.Validate(); err != nil {
			fail(err)
			continue
		}
		if p.AS2ID == sys.Local.AS2ID {
			fail(errors.New("this is the local station's AS2 ID"))
			continue
		}
		if _, dup := set.AS2[p.AS2ID]; dup {
			fail(errors.New("defined twice"))
			continue
		}
		ap := &as2.Partner{ID: p.AS2ID, Cert: e.Cert, RequireEncryption: p.RequireEncryption, RequireSignature: p.RequireSignature}
		set.AS2[p.AS2ID] = ap

		if o := p.Outbound; o != nil {
			opts := o.SendOptions(sys.PublicURL)
			switch {
			case !canSend:
				fail(errors.New("sending needs spool_dir in config.json, and a restart"))
			case o.MDN == "async" && opts.AsyncMDNURL == "":
				fail(errors.New("async MDNs need public_url in config.json, or an async MDN URL for this partner"))
			default:
				set.Outbound[p.AS2ID] = &outbound.Partner{Partner: ap, URL: o.URL, Options: opts}
			}
		}
		if f := p.Forward; f != nil {
			client, err := forward.NewClient(f.CAFile, f.Timeout.Duration)
			if err != nil {
				fail(fmt.Errorf("forward: %w", err))
				continue
			}
			password, err := forward.ReadSecret(f.PasswordFile)
			if err != nil {
				fail(fmt.Errorf("forward: %w", err))
				continue
			}
			t := &forward.Target{URL: f.URL, Username: f.Username, Password: password, Client: client}
			rule := &server.ForwardRule{Target: t, BeforeMDN: f.Mode == config.ForwardBeforeMDN}
			if !rule.BeforeMDN {
				if !canSend {
					fail(errors.New("queued forwarding needs spool_dir in config.json, and a restart"))
					continue
				}
				set.Queued[p.AS2ID] = t
			}
			set.Forwards[p.AS2ID] = rule
		}
		set.Entries = append(set.Entries, e)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	slices.SortFunc(set.Entries, func(a, b Entry) int { return strings.Compare(a.Config.AS2ID, b.Config.AS2ID) })
	return set, nil
}

// ParseCertificate reads a certificate given as PEM, or as DER in base64,
// and returns it with its PEM encoding.
func ParseCertificate(data string) (*x509.Certificate, []byte, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, nil, errors.New("no certificate given")
	}
	var der []byte
	if block, _ := pem.Decode([]byte(data)); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("that is a %s, not a certificate", strings.ToLower(block.Type))
		}
		der = block.Bytes
	} else {
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(data), ""))
		if err != nil {
			return nil, nil, errors.New("the certificate must be PEM or base64-encoded DER")
		}
		der = b
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("not a valid certificate: %w", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}
