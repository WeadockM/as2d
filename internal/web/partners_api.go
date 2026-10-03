package web

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/WeadockM/as2d/internal/accounts"
	"github.com/WeadockM/as2d/internal/config"
	"github.com/WeadockM/as2d/internal/partners"
)

// partnerInput is a partner as the dashboard's edit form sends it.
type partnerInput struct {
	AS2ID             string         `json:"as2_id"`
	RequireEncryption bool           `json:"require_encryption"`
	RequireSignature  bool           `json:"require_signature"`
	Outbound          *outboundInput `json:"outbound"` // null: don't send to this partner
	Certificate       string         `json:"certificate"`
}

type outboundInput struct {
	URL         string `json:"url"`
	Encrypt     bool   `json:"encrypt"`
	Sign        bool   `json:"sign"`
	SignedMDN   bool   `json:"signed_mdn"`
	Cipher      string `json:"cipher"`
	MICAlg      string `json:"micalg"`
	Compress    string `json:"compress"`
	MDN         string `json:"mdn"`
	AsyncMDNURL string `json:"async_mdn_url"`
}

func (o *outboundInput) config() *config.Outbound {
	if o == nil {
		return nil
	}
	b := func(v bool) *bool { return &v }
	return &config.Outbound{
		URL: strings.TrimSpace(o.URL), Encrypt: b(o.Encrypt), Sign: b(o.Sign), SignedMDN: b(o.SignedMDN),
		Cipher: o.Cipher, MICAlg: o.MICAlg, Compress: o.Compress, MDN: o.MDN, AsyncMDNURL: strings.TrimSpace(o.AsyncMDNURL),
	}
}

func (s *site) partnersEditable(w http.ResponseWriter) bool {
	if !s.cfg.Partners.Editable() {
		apiError(w, http.StatusConflict, partners.ErrNoStore.Error())
		return false
	}
	return true
}

func (s *site) getPartner(w http.ResponseWriter, r *http.Request) {
	e, ok := s.cfg.Partners.Current().Entry(r.PathValue("id"))
	if !ok {
		apiError(w, http.StatusNotFound, "no such partner")
		return
	}
	resp := map[string]any{"partner": describePartner(e)}
	if s.cfg.Queue != nil {
		resp["pending"] = s.cfg.Queue.Pending(e.Config.AS2ID)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *site) inspectCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Certificate string `json:"certificate"`
	}
	if !decode(w, r, &req) {
		return
	}
	cert, _, err := partners.ParseCertificate(req.Certificate)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, describeCert(cert))
}

// partnerError answers for a failed partner change.
func partnerError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, partners.ErrNotFound):
		apiError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, partners.ErrNoStore), errors.Is(err, partners.ErrPending):
		apiError(w, http.StatusConflict, err.Error())
	default:
		apiError(w, http.StatusBadRequest, err.Error())
	}
}

func (s *site) recordPartner(r *http.Request, action, id string, details map[string]any) {
	if s.auth.accounts != nil {
		s.auth.accounts.Store.Record(accounts.Entry{User: actor(r), Action: action, Target: id, Remote: remoteAddr(r), Details: details})
	}
	s.cfg.Log.Info("partner changed", "action", action, "partner", id, "by", actor(r))
}

func (s *site) createPartner(w http.ResponseWriter, r *http.Request) {
	if !s.partnersEditable(w) {
		return
	}
	var in partnerInput
	if !decode(w, r, &in) {
		return
	}
	in.AS2ID = strings.TrimSpace(in.AS2ID)
	if e, ok := s.cfg.Partners.Current().Entry(in.AS2ID); ok {
		msg := "a partner with this AS2 ID already exists"
		if e.Source == partners.FromConfig {
			msg = "this partner is defined in config.json; import it to edit it here"
		}
		apiError(w, http.StatusConflict, msg)
		return
	}
	cert, certPEM, err := partners.ParseCertificate(in.Certificate)
	if err != nil {
		apiError(w, http.StatusBadRequest, "certificate: "+err.Error())
		return
	}
	rec, err := s.cfg.Partners.Save(partners.Record{
		AS2ID: in.AS2ID, RequireEncryption: in.RequireEncryption, RequireSignature: in.RequireSignature,
		Outbound: in.Outbound.config(),
	}, certPEM, actor(r), "created")
	if err != nil {
		partnerError(w, err)
		return
	}
	s.recordPartner(r, "partner_create", rec.AS2ID, map[string]any{"certificate": describeCert(cert).SHA256})
	s.respondPartner(w, http.StatusCreated, rec.AS2ID)
}

func (s *site) updatePartner(w http.ResponseWriter, r *http.Request) {
	if !s.partnersEditable(w) {
		return
	}
	id := r.PathValue("id")
	old, _, err := s.cfg.Partners.Store.Get(id)
	if err != nil {
		if errors.Is(err, partners.ErrNotFound) {
			err = errors.New("this partner is not managed in the dashboard; import it from config.json first")
		}
		partnerError(w, err)
		return
	}
	var in partnerInput
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.AS2ID) != "" && in.AS2ID != id {
		apiError(w, http.StatusBadRequest, "the AS2 ID can't be changed; add a new partner instead")
		return
	}
	next := old
	next.RequireEncryption, next.RequireSignature, next.Outbound = in.RequireEncryption, in.RequireSignature, in.Outbound.config()

	var certPEM []byte
	details := changedFields(old, next)
	if strings.TrimSpace(in.Certificate) != "" {
		cert, p, err := partners.ParseCertificate(in.Certificate)
		if err != nil {
			apiError(w, http.StatusBadRequest, "certificate: "+err.Error())
			return
		}
		certPEM = p
		if before, ok := s.cfg.Partners.Current().Entry(id); !ok || !before.Cert.Equal(cert) {
			details["certificate"] = describeCert(cert).SHA256
		}
	}
	if len(details) == 0 {
		s.respondPartner(w, http.StatusOK, id) // nothing changed; no new version
		return
	}
	if _, err := s.cfg.Partners.Save(next, certPEM, actor(r), "updated"); err != nil {
		partnerError(w, err)
		return
	}
	s.recordPartner(r, "partner_update", id, details)
	s.respondPartner(w, http.StatusOK, id)
}

// changedFields lists what differs between two versions, for the audit log.
func changedFields(old, next partners.Record) map[string]any {
	out := map[string]any{}
	if old.RequireEncryption != next.RequireEncryption {
		out["require_encryption"] = next.RequireEncryption
	}
	if old.RequireSignature != next.RequireSignature {
		out["require_signature"] = next.RequireSignature
	}
	switch {
	case old.Outbound == nil && next.Outbound != nil:
		out["outbound"] = "enabled, to " + next.Outbound.URL
	case old.Outbound != nil && next.Outbound == nil:
		out["outbound"] = "disabled"
	case old.Outbound != nil:
		a, b := describeOutbound(old.Outbound), describeOutbound(next.Outbound)
		var keys []string
		for k := range b {
			if !reflect.DeepEqual(a[k], b[k]) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			out["outbound."+k] = fmt.Sprintf("%v → %v", orNone(a[k]), orNone(b[k]))
		}
	}
	return out
}

// summarize writes changedFields' result as one line, e.g.
// "mdn: sync → async; require_signature: false".
func summarize(changes map[string]any) string {
	if len(changes) == 0 {
		return "no settings changed"
	}
	keys := make([]string, 0, len(changes))
	for k := range changes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s: %v", strings.TrimPrefix(k, "outbound."), changes[k])
	}
	return strings.Join(parts, "; ")
}

func describeOutbound(o *config.Outbound) map[string]any {
	return map[string]any{
		"url": o.URL, "encrypt": config.Bool(o.Encrypt), "sign": config.Bool(o.Sign), "signed_mdn": config.Bool(o.SignedMDN),
		"cipher": or(o.Cipher, "aes256-cbc"), "micalg": or(o.MICAlg, "sha-256"), "compress": or(o.Compress, "none"),
		"mdn": or(o.MDN, "sync"), "async_mdn_url": o.AsyncMDNURL,
	}
}

func (s *site) respondPartner(w http.ResponseWriter, status int, id string) {
	e, ok := s.cfg.Partners.Current().Entry(id)
	if !ok {
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, map[string]any{"partner": describePartner(e)})
}

func (s *site) deletePartner(w http.ResponseWriter, r *http.Request) {
	if !s.partnersEditable(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.cfg.Partners.Delete(id, actor(r)); err != nil {
		partnerError(w, err)
		return
	}
	s.recordPartner(r, "partner_delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *site) importPartner(w http.ResponseWriter, r *http.Request) {
	if !s.partnersEditable(w) {
		return
	}
	id := r.PathValue("id")
	if _, err := s.cfg.Partners.Import(id, actor(r)); err != nil {
		partnerError(w, err)
		return
	}
	s.recordPartner(r, "partner_import", id, nil)
	s.respondPartner(w, http.StatusOK, id)
}

func (s *site) partnerHistory(w http.ResponseWriter, r *http.Request) {
	if !s.partnersEditable(w) {
		return
	}
	hist, err := s.cfg.Partners.Store.History(r.PathValue("id"))
	if errors.Is(err, partners.ErrNotFound) {
		writeJSON(w, http.StatusOK, []any{}) // a config.json partner has no dashboard history
		return
	}
	if err != nil {
		partnerError(w, err)
		return
	}
	type version struct {
		partners.Record
		Summary string `json:"summary"`
	}
	// Each version is summarised by what changed from the one before it
	// (history is newest first).
	out := make([]version, len(hist))
	for i, h := range hist {
		summary := "receiving only"
		if h.Outbound != nil {
			summary = "sending to " + h.Outbound.URL
		}
		if i+1 < len(hist) && h.Action != "deleted" && hist[i+1].Action != "deleted" {
			summary = summarize(changedFields(hist[i+1], h))
			_, a, errA := s.cfg.Partners.Store.Version(h.AS2ID, hist[i+1].Version)
			_, b, errB := s.cfg.Partners.Store.Version(h.AS2ID, h.Version)
			if errA == nil && errB == nil && !bytes.Equal(a, b) {
				summary = strings.TrimPrefix(summary+"; new certificate", "no settings changed; ")
			}
		}
		out[i] = version{h, summary}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *site) restorePartner(w http.ResponseWriter, r *http.Request) {
	if !s.partnersEditable(w) {
		return
	}
	id := r.PathValue("id")
	v, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		apiError(w, http.StatusNotFound, "no such version")
		return
	}
	if _, err := s.cfg.Partners.Restore(id, v, actor(r)); err != nil {
		partnerError(w, err)
		return
	}
	s.recordPartner(r, "partner_restore", id, map[string]any{"version": v})
	s.respondPartner(w, http.StatusOK, id)
}

func orNone(v any) any {
	if v == "" {
		return "(none)"
	}
	return v
}
