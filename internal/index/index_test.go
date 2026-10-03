package index_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/index"
)

func openStore(t *testing.T, root string) (*archive.Store, *index.DB, bool) {
	t.Helper()
	db, rebuild, err := index.Open(filepath.Join(root, "as2d.db"), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &archive.Store{Root: root, Index: db, OnIndexError: func(dir string, err error) { t.Errorf("index %s: %v", dir, err) }}, db, rebuild
}

func save(t *testing.T, s *archive.Store, direction, partner, id string, when time.Time, meta map[string]any) string {
	t.Helper()
	b, _ := json.Marshal(meta)
	dir, err := s.Save(direction, partner, id, when, map[string][]byte{"meta.json": b})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// fill archives a small mix of messages.
func fill(t *testing.T, s *archive.Store) (inboundOK string) {
	inboundOK = save(t, s, "inbound", "ACME", "<a@acme>", t0, map[string]any{
		"message_id": "<a@acme>", "as2_from": "ACME", "received": t0, "filename": "po_1001.edi",
		"payload_bytes": 120, "encrypted": true, "signed": true, "disposition": "automatic-action/MDN-sent-automatically; processed",
	})
	save(t, s, "inbound", "ACME", "<b@acme>", t0.Add(time.Minute), map[string]any{
		"message_id": "<b@acme>", "as2_from": "ACME", "received": t0.Add(time.Minute),
		"error": "decryption-failed: bad key",
	})
	save(t, s, "inbound", "GLOBEX", "<c@globex>", t0.Add(2*time.Minute), map[string]any{
		"message_id": "<c@globex>", "as2_from": "GLOBEX", "received": t0.Add(2 * time.Minute), "duplicate_of": "/x",
	})
	save(t, s, "outbound", "ACME", "<d@us>", t0.Add(3*time.Minute), map[string]any{
		"id": "job-1", "partner": "ACME", "message_id": "<d@us>", "created": t0.Add(3 * time.Minute),
		"state": "delivered", "filename": "invoice_77.xml", "size": 900, "correlation_id": "boomi-42",
	})
	return inboundOK
}

func TestIndexAndQuery(t *testing.T) {
	root := t.TempDir()
	s, db, rebuild := openStore(t, root)
	if !rebuild {
		t.Error("a new index should ask for a rebuild")
	}
	okDir := fill(t, s)

	all, total, err := db.List(index.Filter{})
	if err != nil || total != 4 || len(all) != 4 {
		t.Fatalf("List: %d of %d, %v", len(all), total, err)
	}
	if all[0].MessageID != "<d@us>" || all[3].MessageID != "<a@acme>" {
		t.Errorf("not newest first: %s ... %s", all[0].MessageID, all[3].MessageID)
	}

	for name, tc := range map[string]struct {
		f    index.Filter
		want []string
	}{
		"partner":       {index.Filter{Partner: "ACME"}, []string{"<d@us>", "<b@acme>", "<a@acme>"}},
		"failed":        {index.Filter{State: index.StateFailed}, []string{"<b@acme>"}},
		"duplicate":     {index.Filter{State: index.StateDuplicate}, []string{"<c@globex>"}},
		"outbound":      {index.Filter{Direction: "outbound"}, []string{"<d@us>"}},
		"filename":      {index.Filter{Search: "PO_1001"}, []string{"<a@acme>"}},
		"correlation":   {index.Filter{Search: "boomi-42"}, []string{"<d@us>"}},
		"like escaping": {index.Filter{Search: "%"}, nil},
		"time range":    {index.Filter{Since: t0.Add(time.Minute), Until: t0.Add(3 * time.Minute)}, []string{"<c@globex>", "<b@acme>"}},
		"paging":        {index.Filter{Limit: 1, Offset: 1}, []string{"<c@globex>"}},
	} {
		got, _, err := db.List(tc.f)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var ids []string
		for _, m := range got {
			ids = append(ids, m.MessageID)
		}
		if len(ids) != len(tc.want) || (len(ids) > 0 && ids[0] != tc.want[0]) || (len(ids) > 1 && ids[len(ids)-1] != tc.want[len(tc.want)-1]) {
			t.Errorf("%s: got %v, want %v", name, ids, tc.want)
		}
	}

	m := all[3]
	got, err := db.Get(m.ID)
	if err != nil || got.ArchiveDir != okDir || !got.Encrypted || got.State != index.StateReceived || got.Size != 120 {
		t.Errorf("Get = %+v, %v", got, err)
	}
	if _, err := db.Get(9999); err != index.ErrNotFound {
		t.Errorf("Get(9999) err = %v", err)
	}

	// A forward finishing later updates the row.
	if err := s.UpdateMeta(okDir, "forward", map[string]any{"mode": "queued", "state": "delivered", "job": "fwd-9"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.Get(m.ID); got.ForwardState != "delivered" || got.JobID != "fwd-9" {
		t.Errorf("after forward update: %+v", got)
	}

	if err := s.MarkSeen("inbound", "ACME", "<a@acme>", okDir); err != nil {
		t.Fatal(err)
	}
	if dir, ok := s.Seen("inbound", "ACME", "<a@acme>"); !ok || dir != okDir {
		t.Errorf("Seen = %q, %v", dir, ok)
	}
	if _, ok := s.Seen("inbound", "GLOBEX", "<a@acme>"); ok {
		t.Error("Seen matched another partner's message")
	}
}

// TestReindex: the database can be thrown away and rebuilt from the archive.
func TestReindex(t *testing.T) {
	root := t.TempDir()
	s, db, _ := openStore(t, root)
	okDir := fill(t, s)
	before, _, _ := db.List(index.Filter{})
	db.Close()

	for _, f := range []string{"as2d.db", "as2d.db-wal", "as2d.db-shm"} {
		os.Remove(filepath.Join(root, f))
	}
	s2, db2, rebuild := openStore(t, root)
	if !rebuild {
		t.Error("a missing index should ask for a rebuild")
	}
	n, err := db2.Reindex()
	if err != nil || n != 4 {
		t.Fatalf("Reindex = %d, %v", n, err)
	}
	after, _, _ := db2.List(index.Filter{})
	for i := range before {
		b, a := before[i], after[i]
		b.ID, a.ID = 0, 0
		if b != a {
			t.Errorf("row %d differs after reindex:\n%+v\n%+v", i, b, a)
		}
	}
	// Successfully received messages count as seen again; failed ones do not.
	if dir, ok := s2.Seen("inbound", "ACME", "<a@acme>"); !ok || dir != okDir {
		t.Errorf("Seen after reindex = %q, %v", dir, ok)
	}
	if _, ok := s2.Seen("inbound", "ACME", "<b@acme>"); ok {
		t.Error("a failed message counts as seen after reindex")
	}

	// Reopening an index of the current version needs no rebuild.
	db2.Close()
	_, _, rebuild = openStore(t, root)
	if rebuild {
		t.Error("reopening asked for a rebuild")
	}
}
