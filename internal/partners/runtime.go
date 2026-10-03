package partners

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/config"
	"github.com/WeadockM/as2d/internal/outbound"
	"github.com/WeadockM/as2d/internal/pki"
	"github.com/WeadockM/as2d/internal/server"
)

// Runtime holds the partners in effect and applies changes to the running
// daemon: the receiver, the inbound server's forward rules and the outbound
// queue. Every change is checked by building the complete new set first, so
// an invalid change is refused before anything is written.
type Runtime struct {
	Sys      *config.Config
	Store    *Store            // nil without state_dir: no dashboard editing
	Receiver *as2.Receiver     // may be nil in tests
	Server   *server.Server    // may be nil in tests
	Manager  *outbound.Manager // nil without spool_dir
	Log      *slog.Logger

	mu             sync.Mutex // serializes changes
	configPartners []config.Partner
	current        atomic.Pointer[Set]
}

// ErrNoStore is returned when partners can't be edited because state_dir
// is not set.
var ErrNoStore = errors.New("editing partners in the dashboard needs state_dir in config.json")

// Current returns the partners in effect.
func (rt *Runtime) Current() *Set {
	if s := rt.current.Load(); s != nil {
		return s
	}
	return &Set{}
}

// Editable reports whether dashboard editing is available.
func (rt *Runtime) Editable() bool { return rt.Store != nil }

// Load reads the dashboard partners, combines them with configPartners and
// applies the result. It is used at startup and when config.json partners
// are reloaded.
func (rt *Runtime) Load(configPartners []config.Partner) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.loadLocked(configPartners)
}

func (rt *Runtime) loadLocked(configPartners []config.Partner) error {
	var records []Record
	if rt.Store != nil {
		var err error
		if records, err = rt.Store.List(); err != nil {
			return err
		}
	}
	set, err := rt.build(configPartners, records, nil)
	if err != nil {
		return err
	}
	rt.configPartners = configPartners
	rt.apply(set)
	for _, e := range set.Entries {
		if e.AlsoInConfig {
			rt.Log.Warn("partner is defined in both config.json and the dashboard; the dashboard's version is used. Remove it from config.json.", "partner", e.Config.AS2ID)
		}
	}
	return nil
}

// build combines config partners and dashboard records into a checked Set.
// certs overrides the stored certificate (PEM) of dashboard records.
func (rt *Runtime) build(configPartners []config.Partner, records []Record, certs map[string][]byte) (*Set, error) {
	var entries []Entry
	inDashboard := map[string]int{}
	for _, r := range records {
		pemData, ok := certs[r.AS2ID]
		if !ok {
			var err error
			if pemData, err = os.ReadFile(rt.Store.CertPath(r.AS2ID)); err != nil {
				return nil, fmt.Errorf("partner %q: certificate: %w", r.AS2ID, err)
			}
		}
		cert, _, err := ParseCertificate(string(pemData))
		if err != nil {
			return nil, fmt.Errorf("partner %q: certificate: %w", r.AS2ID, err)
		}
		rec := r
		inDashboard[r.AS2ID] = len(entries)
		entries = append(entries, Entry{Config: r.Partner(rt.Store.CertPath(r.AS2ID)), Cert: cert, Source: FromDashboard, Record: &rec})
	}
	for _, p := range configPartners {
		if i, ok := inDashboard[p.AS2ID]; ok {
			entries[i].AlsoInConfig = true
			continue
		}
		cert, err := pki.LoadCertificate(p.Cert)
		if err != nil {
			return nil, fmt.Errorf("partner %q (config.json): %w", p.AS2ID, err)
		}
		entries = append(entries, Entry{Config: p, Cert: cert, Source: FromConfig})
	}
	return build(rt.Sys, entries, rt.Manager != nil)
}

func (rt *Runtime) apply(set *Set) {
	if rt.Receiver != nil {
		rt.Receiver.SetPartners(set.AS2)
	}
	if rt.Server != nil {
		rt.Server.SetForwards(set.Forwards)
	}
	if rt.Manager != nil {
		rt.Manager.SetPartners(set.Outbound, set.Queued)
	}
	rt.current.Store(set)
}

// check builds the set that records would give, without applying it.
func (rt *Runtime) check(records []Record, certs map[string][]byte) error {
	_, err := rt.build(rt.configPartners, records, certs)
	return err
}

// Save stores a new version of a dashboard partner and applies it. With a
// nil certPEM the partner keeps its current certificate.
func (rt *Runtime) Save(r Record, certPEM []byte, by, action string) (Record, error) {
	if rt.Store == nil {
		return Record{}, ErrNoStore
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if certPEM == nil {
		_, current, err := rt.Store.Get(r.AS2ID)
		if err != nil {
			return Record{}, err
		}
		certPEM = current
	}
	records, err := rt.Store.List()
	if err != nil {
		return Record{}, err
	}
	replaced := false
	for i := range records {
		if records[i].AS2ID == r.AS2ID {
			records[i], replaced = r, true
		}
	}
	if !replaced {
		records = append(records, r)
	}
	if err := rt.check(records, map[string][]byte{r.AS2ID: certPEM}); err != nil {
		return Record{}, err
	}
	stored, err := rt.Store.put(r, certPEM, by, action)
	if err != nil {
		return Record{}, err
	}
	return stored, rt.loadLocked(rt.configPartners)
}

// ErrPending refuses to delete a partner with unfinished messages.
var ErrPending = errors.New("this partner still has messages in the queue; wait for them to finish, or for them to fail, first")

// Delete removes a dashboard partner and applies the change. Its history is
// kept. If config.json also defines the partner, that definition takes
// over again.
func (rt *Runtime) Delete(id, by string) error {
	if rt.Store == nil {
		return ErrNoStore
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if _, _, err := rt.Store.Get(id); err != nil {
		return err
	}
	if rt.Manager != nil && rt.Manager.Pending(id) > 0 {
		return ErrPending
	}
	records, err := rt.Store.List()
	if err != nil {
		return err
	}
	var rest []Record
	for _, r := range records {
		if r.AS2ID != id {
			rest = append(rest, r)
		}
	}
	if err := rt.check(rest, nil); err != nil {
		return err
	}
	if err := rt.Store.remove(id, by); err != nil {
		return err
	}
	return rt.loadLocked(rt.configPartners)
}

// Restore makes an earlier version of a dashboard partner current again.
func (rt *Runtime) Restore(id string, version int, by string) (Record, error) {
	if rt.Store == nil {
		return Record{}, ErrNoStore
	}
	r, certPEM, err := rt.Store.Version(id, version)
	if err != nil {
		return Record{}, err
	}
	return rt.Save(r, certPEM, by, fmt.Sprintf("restored version %d", version))
}

// Import copies a partner from config.json into the dashboard. From then
// on the dashboard's copy is used; the config.json entry should be removed.
func (rt *Runtime) Import(id, by string) (Record, error) {
	if rt.Store == nil {
		return Record{}, ErrNoStore
	}
	rt.mu.Lock()
	var p *config.Partner
	for i := range rt.configPartners {
		if rt.configPartners[i].AS2ID == id {
			p = &rt.configPartners[i]
		}
	}
	rt.mu.Unlock()
	if p == nil {
		return Record{}, fmt.Errorf("config.json has no partner %q", id)
	}
	if _, _, err := rt.Store.Get(id); err == nil {
		return Record{}, errors.New("this partner is already in the dashboard")
	}
	pemData, err := os.ReadFile(p.Cert)
	if err != nil {
		return Record{}, err
	}
	_, certPEM, err := ParseCertificate(string(pemData))
	if err != nil {
		return Record{}, err
	}
	return rt.Save(Record{
		AS2ID: p.AS2ID, RequireEncryption: p.RequireEncryption, RequireSignature: p.RequireSignature,
		Outbound: p.Outbound, Forward: p.Forward,
	}, certPEM, by, "imported from config.json")
}

// Static returns a Runtime with a fixed set of partners and no editing,
// for tests and tools.
func Static(entries ...Entry) *Runtime {
	rt := &Runtime{}
	set := &Set{Entries: entries}
	rt.current.Store(set)
	return rt
}
