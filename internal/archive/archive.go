// Package archive stores messages on local disk.
package archive

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/WeadockM/as2d/internal/index"
)

// Store writes each message to its own directory:
//
//	<Root>/<direction>/<partner>/<yyyy>/<mm>/<dd>/<hhmmss.micros>_<message-id>/
type Store struct {
	Root string

	// Index, if set, is kept up to date with every message saved, and holds
	// the record of processed Message-IDs. Indexing failures do not fail a
	// save, since the files are the source of truth; they are reported to
	// OnIndexError and repaired by a reindex.
	Index        *index.DB
	OnIndexError func(dir string, err error)

	metaMu sync.Mutex // serializes meta.json read-modify-writes
}

func (s *Store) index(dir string) {
	if s.Index == nil {
		return
	}
	if err := s.Index.Add(dir); err != nil && s.OnIndexError != nil {
		s.OnIndexError(dir, err)
	}
}

// Save writes files (keyed by slash-separated relative path) into a new
// message directory and returns its path. Files are fsynced and the
// directory only appears under its final name once every file is written.
func (s *Store) Save(direction, partner, messageID string, t time.Time, files map[string][]byte) (string, error) {
	t = t.UTC()
	parent := filepath.Join(s.Root, direction, SafeName(partner), t.Format("2006"), t.Format("01"), t.Format("02"))
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return "", fmt.Errorf("archive: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, ".tmp-")
	if err != nil {
		return "", fmt.Errorf("archive: %w", err)
	}
	done := false
	defer func() {
		if !done {
			os.RemoveAll(tmp)
		}
	}()

	for name, data := range files {
		if err := writeFile(filepath.Join(tmp, filepath.FromSlash(name)), data); err != nil {
			return "", fmt.Errorf("archive: %w", err)
		}
	}

	base := t.Format("150405.000000") + "_" + SafeName(messageID)
	dest := filepath.Join(parent, base)
	for n := 2; ; n++ {
		err := os.Rename(tmp, dest)
		if err == nil {
			break
		}
		if _, statErr := os.Stat(dest); statErr != nil {
			return "", fmt.Errorf("archive: %w", err) // failed for a reason other than a name collision
		}
		dest = filepath.Join(parent, fmt.Sprintf("%s-%d", base, n))
	}
	done = true
	syncDir(parent)
	s.index(dest)
	return dest, nil
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// syncDir makes a rename durable on Linux. It is best effort: directories
// cannot be synced on every platform.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

// SafeName turns an untrusted string into a single, harmless path element.
func SafeName(s string) string {
	s = strings.Trim(s, "<> ")
	s = strings.Map(func(r rune) rune {
		if r < 0x80 && (r == '.' || r == '-' || r == '_' || r == '@' ||
			r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return r
		}
		return '_'
	}, s)
	s = strings.TrimLeft(s, ".")
	if len(s) > 100 {
		s = s[:100]
	}
	if s == "" {
		return "_"
	}
	return s
}
