package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExampleConfigLoads(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "deploy", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := c.Partners[0].Forward
	// Relative paths are resolved against the config file's directory.
	if f == nil || f.Mode != ForwardQueued || f.Timeout.Duration != 60*time.Second ||
		f.PasswordFile != filepath.Join("..", "..", "deploy", "boomi.pass") {
		t.Errorf("forward = %+v", f)
	}
	if c.StatusWebhook == nil || c.StatusWebhook.Timeout.Duration != 30*time.Second {
		t.Errorf("status_webhook = %+v", c.StatusWebhook)
	}
	if !c.NeedsQueue() {
		t.Error("NeedsQueue = false")
	}
}

func TestForwardDefaultsAndValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(forward string) error {
		cfg := `{"local":{"as2_id":"A","cert":"a.crt","key":"a.key"},
		         "partners":[{"as2_id":"B","cert":"b.crt","forward":` + forward + `}]}`
		path := filepath.Join(dir, "c.json")
		os.WriteFile(path, []byte(cfg), 0o600)
		_, err := Load(path)
		return err
	}
	if err := write(`{"url":"http://x"}`); err != nil {
		t.Errorf("minimal forward: %v", err)
	}
	for forward, want := range map[string]string{
		`{"url":"http://x","mode":"later"}`:      "mode must be queued or before_mdn",
		`{"url":"http://x","username":"u"}`:      "username and password_file go together",
		`{"mode":"queued"}`:                      "url is required",
		`{"url":"http://x","timeout":"forever"}`: "invalid duration",
	} {
		if err := write(forward); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", forward, err, want)
		}
	}
}
