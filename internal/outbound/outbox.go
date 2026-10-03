package outbound

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/WeadockM/as2d/internal/archive"
)

// settle is how long a file must go unmodified before it is picked up, so
// files still being copied in are left alone.
const settle = 3 * time.Second

// WatchOutbox sends files dropped into <dir>/<partner>/ until ctx is
// canceled. Hidden files and names ending in .tmp or .part are ignored, so
// writers can create a file under such a name and rename it when complete.
// Files that cannot be queued are moved to <dir>/<partner>/rejected/.
func (m *Manager) WatchOutbox(ctx context.Context, dir string, interval time.Duration) {
	m.cfg.Log.Info("watching outbox", "dir", dir)
	created := map[string]bool{} // folders already made
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		// Partners can be added and removed while running, so the folder
		// list is worked out again on every scan.
		for _, id := range m.partnerIDs() {
			path := filepath.Join(dir, archive.SafeName(id))
			if !created[path] {
				if err := os.MkdirAll(path, 0o750); err != nil {
					m.cfg.Log.Error("cannot create outbox folder", "dir", path, "err", err)
					continue
				}
				created[path] = true
			}
			m.scanOutbox(path, id)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (m *Manager) scanOutbox(folder, partner string) {
	entries, err := os.ReadDir(folder)
	if err != nil {
		m.cfg.Log.Warn("cannot read outbox folder", "dir", folder, "err", err)
		return
	}
	for _, e := range entries {
		name := e.Name()
		lower := strings.ToLower(name)
		if !e.Type().IsRegular() || strings.HasPrefix(name, ".") ||
			strings.HasSuffix(lower, ".tmp") || strings.HasSuffix(lower, ".part") {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < settle {
			continue
		}
		path := filepath.Join(folder, name)
		data, err := os.ReadFile(path)
		if err != nil {
			m.cfg.Log.Warn("cannot read outbox file", "file", path, "err", err)
			continue
		}
		if _, err := m.Submit(Submission{Partner: partner, Filename: name, Payload: data}); err != nil {
			m.cfg.Log.Error("cannot queue outbox file; moving it aside", "file", path, "err", err)
			rejected := filepath.Join(folder, "rejected")
			os.MkdirAll(rejected, 0o750)
			os.Rename(path, filepath.Join(rejected, name))
			continue
		}
		if err := os.Remove(path); err != nil {
			m.cfg.Log.Error("queued outbox file but could not remove it; it may be sent twice", "file", path, "err", err)
		}
	}
}
