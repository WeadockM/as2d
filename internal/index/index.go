// Package index keeps a SQLite index of the message archive for searching
// and listing. The archive's files remain the source of truth: every row is
// derived from a message directory's meta.json, so the database can be
// deleted and rebuilt with Reindex at any time.
package index

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go; no C compiler needed
)

// schemaVersion is bumped whenever the schema changes. An index with another
// version is dropped and rebuilt from the archive.
const schemaVersion = 1

const schema = `
CREATE TABLE messages (
	id             INTEGER PRIMARY KEY,
	archive_dir    TEXT NOT NULL UNIQUE, -- relative to the archive root, slash-separated
	direction      TEXT NOT NULL,        -- inbound or outbound
	partner        TEXT NOT NULL,
	message_id     TEXT NOT NULL,
	time           TEXT NOT NULL,        -- fixed-width UTC, so it sorts as text
	state          TEXT NOT NULL,
	filename       TEXT NOT NULL,
	content_type   TEXT NOT NULL,
	subject        TEXT NOT NULL,
	size           INTEGER NOT NULL,
	encrypted      INTEGER NOT NULL,
	signed         INTEGER NOT NULL,
	compressed     INTEGER NOT NULL,
	disposition    TEXT NOT NULL,
	mic            TEXT NOT NULL,
	error          TEXT NOT NULL,
	forward_state  TEXT NOT NULL,
	correlation_id TEXT NOT NULL,
	job_id         TEXT NOT NULL
);
CREATE INDEX messages_time ON messages (time DESC);
CREATE INDEX messages_partner_time ON messages (partner, time DESC);
CREATE INDEX messages_message_id ON messages (message_id);

-- Message-IDs processed successfully, for duplicate detection.
CREATE TABLE seen (
	direction   TEXT NOT NULL,
	partner     TEXT NOT NULL,
	message_id  TEXT NOT NULL,
	archive_dir TEXT NOT NULL,
	PRIMARY KEY (direction, partner, message_id)
);
`

const timeLayout = "2006-01-02T15:04:05.000000Z"

// Message states as indexed.
const (
	StateReceived  = "received"  // inbound, processed successfully
	StateDuplicate = "duplicate" // inbound, Message-ID seen before; not delivered again
	StateFailed    = "failed"    // inbound processing or forward failed, or outbound gave up
	StateDelivered = "delivered" // outbound, partner's MDN checked out
)

// Message is one archived message.
type Message struct {
	ID            int64     `json:"id"`
	Direction     string    `json:"direction"`
	Partner       string    `json:"partner"`
	MessageID     string    `json:"message_id"`
	Time          time.Time `json:"time"`
	State         string    `json:"state"`
	Filename      string    `json:"filename,omitempty"`
	ContentType   string    `json:"content_type,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Size          int64     `json:"size"`
	Encrypted     bool      `json:"encrypted"`
	Signed        bool      `json:"signed"`
	Compressed    bool      `json:"compressed"`
	Disposition   string    `json:"disposition,omitempty"`
	MIC           string    `json:"mic,omitempty"`
	Error         string    `json:"error,omitempty"`
	ForwardState  string    `json:"forward_state,omitempty"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	JobID         string    `json:"job_id,omitempty"` // outbound job, or the inbound message's forward job
	ArchiveDir    string    `json:"-"`                // absolute path
}

// DB is the index.
type DB struct {
	db   *sql.DB
	root string // archive root
}

// Open opens or creates the index at path for the archive at root. rebuild
// reports that the index is new or was reset, so the caller should Reindex.
func Open(path, root string) (db *DB, rebuild bool, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, false, err
	}
	sqldb, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, false, err
	}
	// One connection: writes are serialized anyway, and message volumes are
	// modest. It also rules out SQLITE_BUSY between our own connections.
	sqldb.SetMaxOpenConns(1)

	var version int
	if err := sqldb.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		sqldb.Close()
		return nil, false, fmt.Errorf("index %s: %w", path, err)
	}
	if version != schemaVersion {
		if err := reset(sqldb); err != nil {
			sqldb.Close()
			return nil, false, fmt.Errorf("index %s: %w", path, err)
		}
		rebuild = true
	}
	return &DB{db: sqldb, root: root}, rebuild, nil
}

func reset(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{"DROP TABLE IF EXISTS messages", "DROP TABLE IF EXISTS seen", schema,
		fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) Close() error { return d.db.Close() }

// Add indexes (or re-indexes) one message directory from its meta.json.
func (d *DB) Add(dir string) error {
	m, err := d.read(dir)
	if err != nil {
		return err
	}
	return upsert(d.db, m)
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// upsert writes m, whose ArchiveDir is relative to the archive root (see read).
func upsert(db execer, m *Message) error {
	_, err := db.Exec(`INSERT INTO messages (archive_dir, direction, partner, message_id, time, state, filename,
			content_type, subject, size, encrypted, signed, compressed, disposition, mic, error, forward_state,
			correlation_id, job_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (archive_dir) DO UPDATE SET direction = excluded.direction, partner = excluded.partner,
			message_id = excluded.message_id, time = excluded.time, state = excluded.state,
			filename = excluded.filename, content_type = excluded.content_type, subject = excluded.subject,
			size = excluded.size, encrypted = excluded.encrypted, signed = excluded.signed,
			compressed = excluded.compressed, disposition = excluded.disposition, mic = excluded.mic,
			error = excluded.error, forward_state = excluded.forward_state,
			correlation_id = excluded.correlation_id, job_id = excluded.job_id`,
		filepath.ToSlash(m.ArchiveDir), m.Direction, m.Partner, m.MessageID, m.Time.UTC().Format(timeLayout), m.State,
		m.Filename, m.ContentType, m.Subject, m.Size, m.Encrypted, m.Signed, m.Compressed, m.Disposition,
		m.MIC, m.Error, m.ForwardState, m.CorrelationID, m.JobID)
	return err
}

// meta is the union of the inbound and outbound meta.json formats.
type meta struct {
	// Inbound (written by the server package).
	MessageID    string    `json:"message_id"`
	From         string    `json:"as2_from"`
	Received     time.Time `json:"received"`
	Subject      string    `json:"subject"`
	Encrypted    bool      `json:"encrypted"`
	Signed       bool      `json:"signed"`
	Compressed   bool      `json:"compressed"`
	ContentType  string    `json:"content_type"`
	Filename     string    `json:"filename"`
	PayloadBytes int64     `json:"payload_bytes"`
	MIC          string    `json:"mic"`
	Disposition  string    `json:"disposition"`
	Error        string    `json:"error"`
	DuplicateOf  string    `json:"duplicate_of"`
	Forward      *struct {
		Mode  string `json:"mode"`
		State string `json:"state"`
		Job   string `json:"job"`
		Error string `json:"error"`
	} `json:"forward"`

	// Outbound (an outbound.Job).
	JobID         string    `json:"id"`
	Partner       string    `json:"partner"`
	Created       time.Time `json:"created"`
	State         string    `json:"state"`
	Size          int64     `json:"size"`
	LastError     string    `json:"last_error"`
	CorrelationID string    `json:"correlation_id"`
}

// read builds a Message from dir/meta.json. ArchiveDir is set relative to
// the archive root.
func (d *DB) read(dir string) (*Message, error) {
	rel, err := filepath.Rel(d.root, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("index: %s is not inside the archive %s", dir, d.root)
	}
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}
	var mt meta
	if err := json.Unmarshal(b, &mt); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, "meta.json"), err)
	}
	m := &Message{
		Direction:   strings.SplitN(filepath.ToSlash(rel), "/", 2)[0],
		MessageID:   mt.MessageID,
		Filename:    mt.Filename,
		ContentType: mt.ContentType,
		Subject:     mt.Subject,
		MIC:         mt.MIC,
		Disposition: mt.Disposition,
		ArchiveDir:  rel,
	}
	switch m.Direction {
	case "inbound":
		m.Partner, m.Time, m.Size = mt.From, mt.Received, mt.PayloadBytes
		m.Encrypted, m.Signed, m.Compressed = mt.Encrypted, mt.Signed, mt.Compressed
		m.Error = mt.Error
		switch {
		case mt.Error != "":
			m.State = StateFailed
		case mt.DuplicateOf != "":
			m.State = StateDuplicate
		default:
			m.State = StateReceived
		}
		if f := mt.Forward; f != nil {
			m.JobID = f.Job
			m.ForwardState = f.State
			if f.Mode == "before_mdn" {
				m.ForwardState = StateDelivered
				if f.Error != "" {
					// The partner got a 500 and no MDN for this copy.
					m.ForwardState, m.State, m.Error = StateFailed, StateFailed, "forward failed: "+f.Error
				}
			}
		}
	case "outbound":
		m.Partner, m.Time, m.Size = mt.Partner, mt.Created, mt.Size
		m.State, m.Error = mt.State, mt.LastError
		m.CorrelationID, m.JobID = mt.CorrelationID, mt.JobID
	default:
		return nil, fmt.Errorf("index: %s is not under inbound/ or outbound/", dir)
	}
	return m, nil
}

// Seen returns the archive directory of an earlier, successfully processed
// message with this ID from partner.
func (d *DB) Seen(direction, partner, messageID string) (string, bool) {
	var rel string
	err := d.db.QueryRow(`SELECT archive_dir FROM seen WHERE direction = ? AND partner = ? AND message_id = ?`,
		direction, partner, messageID).Scan(&rel)
	if err != nil {
		return "", false
	}
	return filepath.Join(d.root, filepath.FromSlash(rel)), true
}

// MarkSeen records messageID as processed, archived at dir.
func (d *DB) MarkSeen(direction, partner, messageID, dir string) error {
	rel, err := filepath.Rel(d.root, dir)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`INSERT OR REPLACE INTO seen (direction, partner, message_id, archive_dir) VALUES (?, ?, ?, ?)`,
		direction, partner, messageID, filepath.ToSlash(rel))
	return err
}

// Reindex rebuilds the index from every meta.json in the archive. Inbound
// messages that were received successfully are recorded as seen.
func (d *DB) Reindex() (int, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM messages; DELETE FROM seen"); err != nil {
		return 0, err
	}
	n := 0
	for _, direction := range []string{"inbound", "outbound"} {
		top := filepath.Join(d.root, direction)
		err := filepath.WalkDir(top, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && path == top {
					return fs.SkipDir
				}
				return err
			}
			if e.IsDir() && strings.HasPrefix(e.Name(), ".") {
				return fs.SkipDir // half-written messages and other internals
			}
			if e.IsDir() || e.Name() != "meta.json" {
				return nil
			}
			dir := filepath.Dir(path)
			m, err := d.read(dir)
			if err != nil {
				return err
			}
			if err := upsert(tx, m); err != nil {
				return err
			}
			if m.Direction == "inbound" && m.State == StateReceived {
				if _, err := tx.Exec(`INSERT OR REPLACE INTO seen VALUES (?, ?, ?, ?)`,
					"inbound", m.Partner, m.MessageID, filepath.ToSlash(m.ArchiveDir)); err != nil {
					return err
				}
			}
			n++
			return fs.SkipDir // nothing to index below a message directory
		})
		if err != nil {
			return 0, err
		}
	}
	return n, tx.Commit()
}

// Filter selects messages for List. Zero fields match everything.
type Filter struct {
	Direction string
	Partner   string
	State     string
	Search    string // substring of filename, Message-ID, subject or correlation ID
	Since     time.Time
	Until     time.Time
	Limit     int // default 50, at most 500
	Offset    int
}

// List returns matching messages, newest first, and the total number of
// matches ignoring Limit and Offset.
func (d *DB) List(f Filter) ([]Message, int, error) {
	var where []string
	var args []any
	add := func(cond string, arg ...any) {
		where = append(where, cond)
		args = append(args, arg...)
	}
	if f.Direction != "" {
		add("direction = ?", f.Direction)
	}
	if f.Partner != "" {
		add("partner = ?", f.Partner)
	}
	if f.State != "" {
		add("state = ?", f.State)
	}
	if f.Search != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(f.Search) + "%"
		add(`(filename LIKE ? ESCAPE '\' OR message_id LIKE ? ESCAPE '\' OR subject LIKE ? ESCAPE '\'
			OR correlation_id LIKE ? ESCAPE '\')`, like, like, like, like)
	}
	if !f.Since.IsZero() {
		add("time >= ?", f.Since.UTC().Format(timeLayout))
	}
	if !f.Until.IsZero() {
		add("time < ?", f.Until.UTC().Format(timeLayout))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := d.db.QueryRow("SELECT count(*) FROM messages"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 {
		f.Limit = 50
	}
	f.Limit = min(f.Limit, 500)
	rows, err := d.db.Query("SELECT "+columns+" FROM messages"+cond+" ORDER BY time DESC, id DESC LIMIT ? OFFSET ?",
		append(args, f.Limit, max(f.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		m, err := d.scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	return out, total, rows.Err()
}

// ErrNotFound is returned by Get for an unknown ID.
var ErrNotFound = errors.New("index: no such message")

// Get returns one message.
func (d *DB) Get(id int64) (Message, error) {
	m, err := d.scan(d.db.QueryRow("SELECT "+columns+" FROM messages WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Message{}, ErrNotFound
	}
	return m, err
}

// Partners returns the distinct partner IDs in the index.
func (d *DB) Partners() ([]string, error) {
	rows, err := d.db.Query("SELECT DISTINCT partner FROM messages ORDER BY partner")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

const columns = `id, archive_dir, direction, partner, message_id, time, state, filename, content_type, subject,
	size, encrypted, signed, compressed, disposition, mic, error, forward_state, correlation_id, job_id`

func (d *DB) scan(row interface{ Scan(...any) error }) (Message, error) {
	var m Message
	var rel, t string
	err := row.Scan(&m.ID, &rel, &m.Direction, &m.Partner, &m.MessageID, &t, &m.State, &m.Filename,
		&m.ContentType, &m.Subject, &m.Size, &m.Encrypted, &m.Signed, &m.Compressed, &m.Disposition, &m.MIC,
		&m.Error, &m.ForwardState, &m.CorrelationID, &m.JobID)
	if err != nil {
		return Message{}, err
	}
	m.Time, _ = time.Parse(timeLayout, t)
	m.ArchiveDir = filepath.Join(d.root, filepath.FromSlash(rel))
	return m, nil
}
