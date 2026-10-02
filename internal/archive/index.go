package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The index records which Message-IDs were processed successfully, so
// duplicates can be recognized. Each entry is a small file holding the
// archive directory of the original message.

func (s *Store) indexPath(direction, partner, messageID string) string {
	sum := sha256.Sum256([]byte(messageID))
	return filepath.Join(s.Root, ".index", direction, SafeName(partner), hex.EncodeToString(sum[:]))
}

// Seen returns the archive directory of an earlier, successfully processed
// message with this ID from partner.
func (s *Store) Seen(direction, partner, messageID string) (string, bool) {
	b, err := os.ReadFile(s.indexPath(direction, partner, messageID))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// MarkSeen records messageID as processed, archived at dir.
func (s *Store) MarkSeen(direction, partner, messageID, dir string) error {
	p := s.indexPath(direction, partner, messageID)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	return writeFileAtomic(p, []byte(dir))
}

// Deliver writes data as dir/name for another program to pick up. The file
// is written under a hidden temporary name and renamed into place, so it
// never appears half-written. If name is taken, a timestamp is added.
func Deliver(dir, name string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".incoming-")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	name = SafeName(name)
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	dest := filepath.Join(dir, name)
	for n := 1; ; n++ {
		if _, err := os.Lstat(dest); errors.Is(err, os.ErrNotExist) {
			break
		}
		dest = filepath.Join(dir, fmt.Sprintf("%s_%s-%d%s", stem, time.Now().UTC().Format("20060102T150405"), n, ext))
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return "", err
	}
	syncDir(dir)
	return dest, nil
}

// writeFileAtomic replaces path with data via a temporary file and rename.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// UpdateMeta sets one top-level key in a message's meta.json, e.g. to
// record what happened after the message was archived.
func UpdateMeta(dir, key string, value any) error {
	path := filepath.Join(dir, "meta.json")
	var meta map[string]any
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	meta[key] = value
	if b, err = json.MarshalIndent(meta, "", "  "); err != nil {
		return err
	}
	return writeFileAtomic(path, b)
}

// WriteFileAtomic is writeFileAtomic for other packages.
func WriteFileAtomic(path string, data []byte) error { return writeFileAtomic(path, data) }
