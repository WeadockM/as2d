// Command as2send sends one file to a partner over AS2 and checks the MDN.
//
// It reads the same configuration format as as2d: the "local" station is
// the sender, and the partner's "outbound" block says where and how to send.
// Flags override the partner's outbound settings for a single send.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/config"
	"github.com/WeadockM/as2d/internal/outbound"
)

type flags struct {
	config, to, file, contentType, subject     string
	encrypt, sign, signedMDN                   bool
	cipher, micalg, mdn, asyncListen, compress string
	timeout                                    time.Duration
	set                                        map[string]bool // flags given on the command line
}

func main() {
	var f flags
	flag.StringVar(&f.config, "config", "/etc/as2d/config.json", "configuration file")
	flag.StringVar(&f.to, "to", "", "AS2 ID of the partner (default: the only partner with outbound settings)")
	flag.StringVar(&f.file, "file", "", "file to send (required)")
	flag.StringVar(&f.contentType, "content-type", "", "payload content type (default: guessed from the file extension)")
	flag.StringVar(&f.subject, "subject", "", "Subject header")
	flag.BoolVar(&f.encrypt, "encrypt", true, "encrypt the message")
	flag.BoolVar(&f.sign, "sign", true, "sign the message")
	flag.BoolVar(&f.signedMDN, "signed-mdn", true, "ask for a signed MDN")
	flag.StringVar(&f.cipher, "cipher", "", "aes128-cbc, aes256-cbc, aes128-gcm or aes256-gcm")
	flag.StringVar(&f.micalg, "micalg", "", "sha-1, sha-256, sha-384 or sha-512")
	flag.StringVar(&f.mdn, "mdn", "", "sync, async or none")
	flag.StringVar(&f.compress, "compress", "", "none, before-sign or after-sign")
	flag.StringVar(&f.asyncListen, "async-listen", "127.0.0.1:4081", "address to receive an asynchronous MDN on when no async_mdn_url is configured")
	flag.DurationVar(&f.timeout, "timeout", 2*time.Minute, "how long to wait for the response and any asynchronous MDN")
	flag.Parse()
	f.set = map[string]bool{}
	flag.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })

	if f.file == "" {
		flag.Usage()
		os.Exit(2)
	}
	ok, err := run(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "as2send:", err)
		os.Exit(1)
	}
	if !ok {
		os.Exit(1)
	}
}

// run sends the file and reports whether it was delivered successfully.
func run(f flags) (bool, error) {
	cfg, err := config.Load(f.config)
	if err != nil {
		return false, err
	}
	local, partners, err := cfg.Stations()
	if err != nil {
		return false, err
	}
	pcfg, err := pickPartner(cfg, f.to)
	if err != nil {
		return false, err
	}
	partner := partners[pcfg.AS2ID]
	opts, asyncLocal, err := sendOptions(pcfg.Outbound, f)
	if err != nil {
		return false, err
	}

	payload, err := os.ReadFile(f.file)
	if err != nil {
		return false, err
	}
	opts.Filename = filepath.Base(f.file)
	opts.ContentType = f.contentType
	if opts.ContentType == "" {
		opts.ContentType = outbound.ContentTypeFor(f.file)
	}
	opts.Subject = f.subject

	out, err := local.Package(partner, payload, opts)
	if err != nil {
		return false, err
	}

	// Start listening before sending so a fast partner cannot beat us.
	var asyncMDN <-chan capturedMDN
	if asyncLocal {
		if asyncMDN, err = listenForMDN(f.asyncListen, f.timeout); err != nil {
			return false, err
		}
	}

	fmt.Printf("Sending %s (%d bytes, %s) to %s at %s\n", opts.Filename, len(payload), opts.ContentType, partner.ID, pcfg.Outbound.URL)
	fmt.Printf("  Message-ID: %s\n", out.MessageID)
	fmt.Printf("  Security:   %s\n", describe(opts))
	sent := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pcfg.Outbound.URL, bytes.NewReader(out.Body))
	if err != nil {
		return false, err
	}
	req.Header = out.Header.Clone()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	resp.Body.Close()
	if err != nil {
		return false, err
	}
	fmt.Printf("HTTP %s\n", resp.Status)
	if resp.StatusCode/100 != 2 {
		fmt.Printf("  %s\n", strings.TrimSpace(string(respBody)))
		save(cfg, partner.ID, out, payload, opts, sent, nil, nil, "http "+resp.Status)
		return false, nil
	}

	var mdnHeader http.Header
	var mdnBody []byte
	switch {
	case !opts.RequestMDN:
		fmt.Println("No MDN requested; delivered.")
		save(cfg, partner.ID, out, payload, opts, sent, nil, nil, "")
		return true, nil
	case opts.AsyncMDNURL != "":
		if !asyncLocal {
			fmt.Printf("MDN will be delivered asynchronously to %s.\n", opts.AsyncMDNURL)
			save(cfg, partner.ID, out, payload, opts, sent, nil, nil, "")
			return true, nil
		}
		fmt.Printf("Waiting for asynchronous MDN on %s ...\n", opts.AsyncMDNURL)
		m, ok := <-asyncMDN
		if !ok {
			save(cfg, partner.ID, out, payload, opts, sent, nil, nil, "no asynchronous MDN received")
			return false, errors.New("no asynchronous MDN received before the timeout")
		}
		mdnHeader, mdnBody = m.header, m.body
	default:
		mdnHeader, mdnBody = resp.Header, respBody
	}

	rc, err := as2.ParseMDN(partner, mdnHeader, mdnBody)
	if err == nil {
		err = rc.Match(out.Sent)
	}
	if err != nil {
		save(cfg, partner.ID, out, payload, opts, sent, mdnHeader, mdnBody, err.Error())
		return false, err
	}
	signed := "unsigned"
	if rc.Signed {
		signed = "signature verified"
	}
	fmt.Printf("MDN %s (%s)\n", rc.MessageID, signed)
	fmt.Printf("  Disposition: %s\n", rc.Disposition)
	if rc.MIC != "" {
		match := "DOES NOT MATCH"
		if rc.MICMatches {
			match = "matches"
		}
		fmt.Printf("  MIC:         %s, %s (%s)\n", rc.MIC, rc.MICAlg, match)
	}

	delivered := rc.Processed && rc.MICMatches
	problem := ""
	switch {
	case !rc.Processed:
		problem = "partner reported " + rc.Disposition
	case !rc.MICMatches:
		problem = "MIC in MDN does not match what was sent"
	}
	if dir := save(cfg, partner.ID, out, payload, opts, sent, mdnHeader, mdnBody, problem); dir != "" {
		fmt.Printf("Archived to %s\n", dir)
	}
	if delivered {
		fmt.Println("Result: delivered")
	} else {
		fmt.Println("Result: FAILED -", problem)
	}
	return delivered, nil
}

func pickPartner(cfg *config.Config, id string) (*config.Partner, error) {
	var candidates []*config.Partner
	for i := range cfg.Partners {
		p := &cfg.Partners[i]
		if id != "" && p.AS2ID == id {
			if p.Outbound == nil {
				return nil, fmt.Errorf("partner %q has no outbound settings", id)
			}
			return p, nil
		}
		if p.Outbound != nil {
			candidates = append(candidates, p)
		}
	}
	if id != "" {
		return nil, fmt.Errorf("no partner %q in the configuration", id)
	}
	if len(candidates) != 1 {
		return nil, fmt.Errorf("%d partners have outbound settings; choose one with -to", len(candidates))
	}
	return candidates[0], nil
}

// sendOptions merges the partner's outbound settings with command-line
// overrides. asyncLocal reports whether as2send itself must receive the MDN.
func sendOptions(o *config.Outbound, f flags) (opts as2.SendOptions, asyncLocal bool, err error) {
	opts = as2.SendOptions{
		Encrypt:     config.Bool(o.Encrypt),
		Sign:        config.Bool(o.Sign),
		SignedMDN:   config.Bool(o.SignedMDN),
		Cipher:      o.Cipher,
		MICAlg:      o.MICAlg,
		AsyncMDNURL: o.AsyncMDNURL,
		Compress:    o.Compress,
	}
	mode := o.MDN
	if f.set["encrypt"] {
		opts.Encrypt = f.encrypt
	}
	if f.set["sign"] {
		opts.Sign = f.sign
	}
	if f.set["signed-mdn"] {
		opts.SignedMDN = f.signedMDN
	}
	if f.set["cipher"] {
		opts.Cipher = f.cipher
	}
	if f.set["micalg"] {
		opts.MICAlg = f.micalg
	}
	if f.set["compress"] {
		opts.Compress = f.compress
	}
	if opts.Compress == "none" {
		opts.Compress = ""
	}
	if f.set["mdn"] {
		mode = f.mdn
	}
	switch mode {
	case "", "sync":
		opts.RequestMDN, opts.AsyncMDNURL = true, ""
	case "none":
		opts.RequestMDN, opts.AsyncMDNURL = false, ""
	case "async":
		opts.RequestMDN = true
		if f.set["async-listen"] || opts.AsyncMDNURL == "" {
			opts.AsyncMDNURL = "http://" + f.asyncListen + "/mdn"
			asyncLocal = true
		}
	default:
		return opts, false, fmt.Errorf("-mdn must be sync, async or none, not %q", mode)
	}
	return opts, asyncLocal, nil
}

type capturedMDN struct {
	header http.Header
	body   []byte
}

// listenForMDN accepts one asynchronous MDN on addr. The channel is closed
// without a value if none arrives within timeout.
func listenForMDN(addr string, timeout time.Duration) (<-chan capturedMDN, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("async MDN listener: %w", err)
	}
	ch := make(chan capturedMDN, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		if r.Method != http.MethodPost || err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		select {
		case ch <- capturedMDN{r.Header.Clone(), body}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	})
	go srv.Serve(ln)
	out := make(chan capturedMDN)
	go func() {
		defer close(out)
		defer srv.Close()
		select {
		case m := <-ch:
			out <- m
		case <-time.After(timeout):
		}
	}()
	return out, nil
}

func describe(o as2.SendOptions) string {
	var parts []string
	if o.Sign {
		parts = append(parts, "signed ("+or(o.MICAlg, "sha-256")+")")
	} else {
		parts = append(parts, "unsigned")
	}
	if o.Encrypt {
		parts = append(parts, "encrypted ("+or(o.Cipher, "aes256-cbc")+")")
	} else {
		parts = append(parts, "not encrypted")
	}
	if o.Compress != "" {
		parts = append(parts, "compressed ("+o.Compress+")")
	}
	switch {
	case !o.RequestMDN:
		parts = append(parts, "no MDN")
	case o.AsyncMDNURL != "":
		parts = append(parts, "async MDN")
	default:
		parts = append(parts, "sync MDN")
	}
	if o.RequestMDN && o.SignedMDN {
		parts[len(parts)-1] = "signed " + parts[len(parts)-1]
	}
	return strings.Join(parts, ", ")
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// save archives the sent message and any MDN when archive_dir is set, and
// returns the directory written ("" if none).
func save(cfg *config.Config, partner string, out *as2.Outbound, payload []byte, opts as2.SendOptions,
	sent time.Time, mdnHeader http.Header, mdnBody []byte, problem string) string {
	if cfg.ArchiveDir == "" {
		return ""
	}
	sum := sha256.Sum256(payload)
	meta := map[string]any{
		"message_id":     out.MessageID,
		"to":             partner,
		"sent":           sent.UTC(),
		"security":       describe(opts),
		"filename":       opts.Filename,
		"content_type":   opts.ContentType,
		"payload_bytes":  len(payload),
		"payload_sha256": hex.EncodeToString(sum[:]),
		"expected_mics":  out.MICs,
		"delivered":      problem == "",
	}
	if problem != "" {
		meta["error"] = problem
	}
	files := map[string][]byte{
		"request.http": out.Bytes(),
		"payload/" + archive.SafeName(opts.Filename): payload,
	}
	if mdnHeader != nil {
		var b bytes.Buffer
		mdnHeader.Write(&b)
		b.WriteString("\r\n")
		b.Write(mdnBody)
		files["mdn.http"] = b.Bytes()
	}
	files["meta.json"], _ = json.MarshalIndent(meta, "", "  ")
	dir, err := (&archive.Store{Root: cfg.ArchiveDir}).Save("outbound", partner, out.MessageID, sent, files)
	if err != nil {
		fmt.Fprintln(os.Stderr, "as2send: archive:", err)
		return ""
	}
	return dir
}
