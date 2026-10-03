// Package server exposes the AS2 receiver over HTTP.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/forward"
	"github.com/WeadockM/as2d/internal/outbound"
)

// Server handles inbound AS2 requests: it unwraps each message, archives it
// and returns or sends the MDN.
type Server struct {
	Receiver *as2.Receiver
	Archive  *archive.Store
	Log      *slog.Logger
	MaxBody  int64

	// InboxDir, if set, receives a copy of each successfully received
	// payload under <InboxDir>/<partner>/ for other programs to pick up.
	InboxDir string

	// MDNs receives asynchronous MDNs for messages we sent. Without it,
	// MDNs posted to this endpoint are rejected.
	MDNs MDNHandler

	// Forwards pass received payloads on to another system, by partner.
	Forwards map[string]*ForwardRule // replace with SetForwards once serving
	// Queue takes forwards in queued mode.
	Queue ForwardQueue

	// Client and RetryDelays control delivery of asynchronous MDNs. Each
	// delay precedes one attempt.
	Client      *http.Client
	RetryDelays []time.Duration

	ctx    context.Context // canceled when Shutdown gives up waiting
	cancel context.CancelFunc
	wg     sync.WaitGroup // pending asynchronous MDNs

	mu       sync.Mutex
	inFlight map[string]bool // partner + Message-ID of messages being processed

	fmu sync.RWMutex // guards Forwards
}

// MDNHandler accepts asynchronous MDNs.
type MDNHandler interface {
	HandleMDN(h http.Header, body []byte) error
}

// ForwardRule says where a partner's payloads go and when.
type ForwardRule struct {
	Target *forward.Target
	// BeforeMDN forwards synchronously and withholds the MDN until the
	// target accepts the payload. Otherwise the forward is queued and the
	// MDN is sent at once.
	BeforeMDN bool
}

// ForwardQueue accepts forwards in queued mode.
type ForwardQueue interface {
	SubmitForward(partner string, msg forward.Message, inboundDir string) (outbound.Job, error)
}

func New(rcv *as2.Receiver, store *archive.Store, log *slog.Logger, maxBody int64) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		Receiver:    rcv,
		Archive:     store,
		Log:         log,
		MaxBody:     maxBody,
		Client:      &http.Client{Timeout: 60 * time.Second},
		RetryDelays: []time.Duration{0, 10 * time.Second, time.Minute, 5 * time.Minute},
		ctx:         ctx,
		cancel:      cancel,
		inFlight:    map[string]bool{},
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	received := time.Now()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.MaxBody))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	if as2.IsMDN(r.Header, body) {
		s.handleMDN(w, r, body)
		return
	}

	msg, err := s.Receiver.Process(r.Header, body)
	if err != nil {
		s.Log.Warn("rejected AS2 request", "remote", r.RemoteAddr, "message_id", r.Header.Get("Message-Id"), "err", err)
		status := http.StatusBadRequest
		if errors.Is(err, as2.ErrUnknownPartner) || errors.Is(err, as2.ErrUnknownRecipient) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}

	// Concurrent copies of one message (a sender retrying too eagerly) are
	// turned away so only one of them is delivered.
	key := msg.From + "\x00" + msg.ID
	s.mu.Lock()
	busy := s.inFlight[key]
	s.inFlight[key] = true
	s.mu.Unlock()
	if busy {
		http.Error(w, "this message is already being processed; retry later", http.StatusServiceUnavailable)
		return
	}
	defer func() {
		s.mu.Lock()
		delete(s.inFlight, key)
		s.mu.Unlock()
	}()

	var original string
	if msg.Failure == nil {
		if dir, seen := s.Archive.Seen("inbound", msg.From, msg.ID); seen {
			msg.Warning = as2.WarnDuplicateDocument
			original = dir
		}
	}

	var mdn *as2.MDN
	if msg.Receipt != nil {
		if mdn, err = s.Receiver.BuildMDN(msg); err != nil {
			s.Log.Error("failed to build MDN", "message_id", msg.ID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	// The MDN is only released once the message is safely on disk (and in
	// the inbox). If that fails the sender gets a 500 and will retry.
	dir, err := s.Archive.Save("inbound", msg.From, msg.ID, received, archiveFiles(r, body, msg, mdn, received, original))
	if err != nil {
		s.Log.Error("failed to archive message", "message_id", msg.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	attrs := []any{"message_id", msg.ID, "from", msg.From, "bytes", len(body),
		"encrypted", msg.Encrypted, "signed", msg.Signed, "compressed", msg.Compressed, "archive", dir}

	if msg.Failure == nil && msg.Warning == "" {
		// Delivery: forward and/or inbox. The message is only recorded as
		// seen (and acknowledged) once every step has succeeded; if one
		// fails, the partner gets a 500 and resends.
		rule := s.forwardRule(msg.From)
		fwd := forward.Message{
			From: msg.From, To: msg.To, MessageID: msg.ID, Filename: msg.Filename,
			Subject: msg.Subject, ContentType: msg.ContentType, Payload: msg.Payload,
		}
		if rule != nil && rule.BeforeMDN {
			start := time.Now()
			status, err := rule.Target.Send(r.Context(), fwd)
			rec := map[string]any{"mode": "before_mdn", "http_status": status, "duration": time.Since(start).Round(time.Millisecond).String()}
			if err != nil {
				rec["error"] = err.Error()
			}
			if merr := s.Archive.UpdateMeta(dir, "forward", rec); merr != nil {
				s.Log.Warn("failed to record forward result", "message_id", msg.ID, "err", merr)
			}
			if err != nil {
				s.Log.Error("forward failed; withholding MDN so the partner resends", append(attrs, "err", err)...)
				http.Error(w, "message could not be delivered downstream; please resend", http.StatusInternalServerError)
				return
			}
			attrs = append(attrs, "forwarded", status)
		}
		if s.InboxDir != "" {
			name := msg.Filename
			if name == "" {
				name = archive.SafeName(msg.ID) + ".bin"
			}
			path, err := archive.Deliver(filepath.Join(s.InboxDir, archive.SafeName(msg.From)), name, msg.Payload)
			if err != nil {
				s.Log.Error("failed to deliver payload to inbox", "message_id", msg.ID, "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			attrs = append(attrs, "inbox", path)
		}
		if rule != nil && !rule.BeforeMDN {
			if s.Queue == nil {
				s.Log.Error("forward is queued but no queue is configured", "message_id", msg.ID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			job, err := s.Queue.SubmitForward(msg.From, fwd, dir)
			if err != nil {
				s.Log.Error("failed to queue forward", "message_id", msg.ID, "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			attrs = append(attrs, "forward_job", job.ID)
		}
		if err := s.Archive.MarkSeen("inbound", msg.From, msg.ID, dir); err != nil {
			s.Log.Warn("failed to record message ID for duplicate detection", "message_id", msg.ID, "err", err)
		}
	}

	switch {
	case msg.Failure != nil:
		s.Log.Warn("message failed", append(attrs, "err", msg.Failure)...)
	case msg.Warning != "":
		s.Log.Warn("duplicate message not delivered again", append(attrs, "original", original)...)
	default:
		s.Log.Info("message received", attrs...)
	}

	switch {
	case mdn == nil:
		w.WriteHeader(http.StatusOK)
	case msg.Receipt.AsyncURL != "":
		w.WriteHeader(http.StatusOK)
		s.wg.Add(1)
		go s.sendAsyncMDN(msg.ID, msg.Receipt.AsyncURL, mdn)
	default:
		for k, v := range mdn.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(http.StatusOK)
		w.Write(mdn.Body)
	}
}

func (s *Server) handleMDN(w http.ResponseWriter, r *http.Request, body []byte) {
	log := s.Log.With("remote", r.RemoteAddr, "from", r.Header.Get("As2-From"), "mdn_message_id", r.Header.Get("Message-Id"))
	if s.MDNs == nil {
		log.Warn("rejected MDN: this daemon sends no messages")
		http.Error(w, "this endpoint does not accept MDNs", http.StatusBadRequest)
		return
	}
	if err := s.MDNs.HandleMDN(r.Header, body); err != nil {
		log.Warn("rejected asynchronous MDN", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Info("asynchronous MDN received")
	w.WriteHeader(http.StatusOK)
}

// Shutdown waits for pending asynchronous MDNs to be delivered, abandoning
// them if ctx expires first.
func (s *Server) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.cancel()
		<-done
		return fmt.Errorf("pending asynchronous MDNs abandoned: %w", ctx.Err())
	}
}

func (s *Server) sendAsyncMDN(messageID, target string, mdn *as2.MDN) {
	defer s.wg.Done()
	log := s.Log.With("message_id", messageID, "mdn_url", target)
	if u, err := url.Parse(target); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		log.Error("invalid Receipt-Delivery-Option URL, MDN not sent")
		return
	}
	var err error
	for _, delay := range s.RetryDelays {
		select {
		case <-time.After(delay):
		case <-s.ctx.Done():
			log.Error("shutting down, asynchronous MDN not sent", "last_err", err)
			return
		}
		if err = s.postMDN(target, mdn); err == nil {
			log.Info("asynchronous MDN sent")
			return
		}
		log.Warn("asynchronous MDN attempt failed", "err", err)
	}
	log.Error("giving up on asynchronous MDN", "err", err)
}

func (s *Server) postMDN(target string, mdn *as2.MDN) error {
	req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, target, bytes.NewReader(mdn.Body))
	if err != nil {
		return err
	}
	req.Header = mdn.Header.Clone()
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("partner responded %s", resp.Status)
	}
	return nil
}

type meta struct {
	MessageID     string    `json:"message_id"`
	From          string    `json:"as2_from"`
	To            string    `json:"as2_to"`
	Subject       string    `json:"subject,omitempty"`
	Received      time.Time `json:"received"`
	RemoteAddr    string    `json:"remote_addr"`
	Encrypted     bool      `json:"encrypted"`
	Signed        bool      `json:"signed"`
	Compressed    bool      `json:"compressed"`
	DuplicateOf   string    `json:"duplicate_of,omitempty"` // archive dir of the original
	ContentType   string    `json:"content_type,omitempty"`
	Filename      string    `json:"filename,omitempty"`
	PayloadBytes  int       `json:"payload_bytes"`
	PayloadSHA256 string    `json:"payload_sha256,omitempty"`
	MIC           string    `json:"mic,omitempty"`
	Disposition   string    `json:"disposition"`
	Error         string    `json:"error,omitempty"`
	MDN           string    `json:"mdn"` // none, sync or async
	MDNMessageID  string    `json:"mdn_message_id,omitempty"`
	MDNURL        string    `json:"mdn_url,omitempty"`
}

func archiveFiles(r *http.Request, body []byte, msg *as2.Message, mdn *as2.MDN, received time.Time, duplicateOf string) map[string][]byte {
	m := meta{
		MessageID:   msg.ID,
		From:        msg.From,
		To:          msg.To,
		Subject:     msg.Subject,
		Received:    received.UTC(),
		RemoteAddr:  r.RemoteAddr,
		Encrypted:   msg.Encrypted,
		Signed:      msg.Signed,
		Compressed:  msg.Compressed,
		DuplicateOf: duplicateOf,
		Disposition: msg.Disposition(),
		MDN:         "none",
	}
	if msg.MIC != "" {
		m.MIC = msg.MIC + ", " + msg.MICAlg
	}

	files := map[string][]byte{}

	var req bytes.Buffer
	fmt.Fprintf(&req, "%s %s %s\r\nHost: %s\r\n", r.Method, r.URL.RequestURI(), r.Proto, r.Host)
	r.Header.Write(&req)
	req.WriteString("\r\n")
	req.Write(body)
	files["request.http"] = req.Bytes()

	switch {
	case msg.Failure != nil:
		m.Error = msg.Failure.Error()
	case duplicateOf != "":
		// The payload is already archived with the original.
	default:
		name := msg.Filename
		if name == "" {
			name = "payload.bin"
		}
		files["payload/"+archive.SafeName(name)] = msg.Payload
		sum := sha256.Sum256(msg.Payload)
		m.ContentType = msg.ContentType
		m.Filename = msg.Filename
		m.PayloadBytes = len(msg.Payload)
		m.PayloadSHA256 = hex.EncodeToString(sum[:])
	}

	if mdn != nil {
		files["mdn.http"] = mdn.Bytes()
		m.MDN = "sync"
		m.MDNMessageID = mdn.MessageID
		if msg.Receipt.AsyncURL != "" {
			m.MDN = "async"
			m.MDNURL = msg.Receipt.AsyncURL
		}
	}

	files["meta.json"], _ = json.MarshalIndent(m, "", "  ")
	return files
}

// SetForwards replaces the forward rules. Messages already being processed
// keep the rule they started with.
func (s *Server) SetForwards(rules map[string]*ForwardRule) {
	s.fmu.Lock()
	s.Forwards = rules
	s.fmu.Unlock()
}

func (s *Server) forwardRule(partner string) *ForwardRule {
	s.fmu.RLock()
	defer s.fmu.RUnlock()
	return s.Forwards[partner]
}
