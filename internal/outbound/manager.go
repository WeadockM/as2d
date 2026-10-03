// Package outbound queues messages for partners and delivers them over AS2,
// retrying until the partner returns a successful MDN.
//
// Each job lives in its own spool directory so the queue survives restarts:
//
//	<spool>/<job-id>/job.json      state (rewritten atomically on every change)
//	<spool>/<job-id>/payload       the file to send
//	<spool>/<job-id>/request.http  the packaged AS2 message, reused for every retry
//	<spool>/<job-id>/mdn.http      the partner's MDN, once received
package outbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/forward"
)

// State of a job.
type State string

const (
	Pending     State = "pending"      // waiting for its next attempt
	AwaitingMDN State = "awaiting_mdn" // sent; waiting for an asynchronous MDN
	Delivered   State = "delivered"    // partner returned a successful MDN (or none was requested)
	Failed      State = "failed"       // gave up; can be retried by hand
)

// Kinds of job.
const (
	KindSend    = ""        // an AS2 message to a partner
	KindForward = "forward" // a received payload to pass to the partner's forward endpoint
)

// Job is one message to deliver.
type Job struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind,omitempty"`
	Partner       string    `json:"partner"`
	Filename      string    `json:"filename"`
	ContentType   string    `json:"content_type"`
	Subject       string    `json:"subject,omitempty"`
	CorrelationID string    `json:"correlation_id,omitempty"` // caller's reference, echoed back
	Size          int       `json:"size"`
	Created       time.Time `json:"created"`

	// Forward jobs: the received message being forwarded.
	Inbound *InboundRef `json:"inbound,omitempty"`
	// LastStatus is the HTTP status of the last forward attempt.
	LastStatus int `json:"last_status,omitempty"`
	// Notified records that the status webhook accepted the final state.
	Notified bool `json:"notified,omitempty"`

	State        State     `json:"state"`
	Attempts     int       `json:"attempts"`
	NextAttempt  time.Time `json:"next_attempt,omitzero"`
	LastAttempt  time.Time `json:"last_attempt,omitzero"`
	MDNDeadline  time.Time `json:"mdn_deadline,omitzero"`
	LastError    string    `json:"last_error,omitempty"`
	Finished     time.Time `json:"finished,omitzero"`
	MessageID    string    `json:"message_id,omitempty"`
	Disposition  string    `json:"disposition,omitempty"`
	MDNMessageID string    `json:"mdn_message_id,omitempty"`
	MIC          string    `json:"mic,omitempty"`
	ArchiveDir   string    `json:"archive_dir,omitempty"`

	Sent *as2.Sent `json:"sent,omitempty"` // set once packaged
}

// InboundRef identifies a received message.
type InboundRef struct {
	From       string `json:"from"`
	To         string `json:"to"`
	MessageID  string `json:"message_id"`
	ArchiveDir string `json:"archive_dir"`
}

func (j *Job) finished() bool { return j.State == Delivered || j.State == Failed }

// Status is the view of a job given to API callers and the status webhook:
// the outcome, without internal bookkeeping or local file paths.
type Status struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind"` // "send" or "forward"
	Partner       string    `json:"partner"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	Filename      string    `json:"filename"`
	ContentType   string    `json:"content_type"`
	Subject       string    `json:"subject,omitempty"`
	Size          int       `json:"size"`
	State         State     `json:"state"`
	Attempts      int       `json:"attempts"`
	Created       time.Time `json:"created"`
	NextAttempt   time.Time `json:"next_attempt,omitzero"`
	Finished      time.Time `json:"finished,omitzero"`
	LastError     string    `json:"last_error,omitempty"`

	// Sends: the AS2 message and the partner's MDN.
	MessageID    string `json:"message_id,omitempty"`
	Disposition  string `json:"disposition,omitempty"`
	MIC          string `json:"mic,omitempty"`
	MDNMessageID string `json:"mdn_message_id,omitempty"`

	// Forwards: the received message and the endpoint's last answer.
	InboundMessageID string `json:"inbound_message_id,omitempty"`
	HTTPStatus       int    `json:"http_status,omitempty"`
}

// Status returns the public view of the job.
func (j Job) Status() Status {
	s := Status{
		ID: j.ID, Kind: "send", Partner: j.Partner, CorrelationID: j.CorrelationID,
		Filename: j.Filename, ContentType: j.ContentType, Subject: j.Subject, Size: j.Size,
		State: j.State, Attempts: j.Attempts, Created: j.Created, Finished: j.Finished,
		LastError: j.LastError, MessageID: j.MessageID, Disposition: j.Disposition,
		MIC: j.MIC, MDNMessageID: j.MDNMessageID, HTTPStatus: j.LastStatus,
	}
	if j.State == Pending {
		s.NextAttempt = j.NextAttempt
	}
	if j.Kind == KindForward {
		s.Kind = KindForward
		s.InboundMessageID = j.Inbound.MessageID
	}
	return s
}

// Partner is a partner we send to.
type Partner struct {
	*as2.Partner
	URL     string
	Options as2.SendOptions // per-message fields (filename etc.) are filled in per job
}

type Config struct {
	Local       as2.Station
	Partners    map[string]*Partner
	SpoolDir    string
	Archive     *archive.Store
	Log         *slog.Logger
	Client      *http.Client
	Workers     int
	MaxAttempts int
	MDNTimeout  time.Duration
	Retention   time.Duration
	Backoff     func(attempt int) time.Duration // delay after the given failed attempt

	// Forwards are the endpoints received payloads are passed to, by
	// partner, for partners that forward in queued mode.
	Forwards map[string]*forward.Target
	// Webhook, if set, is told when each send to a partner is delivered or
	// failed.
	Webhook *forward.Webhook
	// WebhookDelays precede the attempts to notify the webhook.
	WebhookDelays []time.Duration
}

// Manager owns the queue.
type Manager struct {
	cfg Config

	mu          sync.Mutex
	jobs        map[string]*Job
	byMessageID map[string]*Job
	busy        map[string]bool     // jobs a worker is handling
	early       map[string]earlyMDN // async MDNs that arrived while their job was still being sent
	waiters     map[string][]chan struct{}
	wake        chan struct{}
	notify      chan string // job IDs whose final state the webhook should hear about
}

type earlyMDN struct {
	header http.Header
	body   []byte
}

var defaultBackoff = []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}

// DefaultBackoff waits 1m, 2m, 5m, 15m, 30m, then hourly.
func DefaultBackoff(attempt int) time.Duration {
	return defaultBackoff[min(attempt, len(defaultBackoff))-1]
}

// New loads the spool. Call Run to start delivering.
func New(cfg Config) (*Manager, error) {
	if cfg.Backoff == nil {
		cfg.Backoff = DefaultBackoff
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 5 * time.Minute}
	}
	if cfg.WebhookDelays == nil {
		cfg.WebhookDelays = []time.Duration{0, 5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}
	}
	if err := os.MkdirAll(cfg.SpoolDir, 0o750); err != nil {
		return nil, err
	}
	m := &Manager{
		cfg:         cfg,
		jobs:        map[string]*Job{},
		byMessageID: map[string]*Job{},
		busy:        map[string]bool{},
		early:       map[string]earlyMDN{},
		waiters:     map[string][]chan struct{}{},
		wake:        make(chan struct{}, 1),
		notify:      make(chan string, 1024),
	}
	entries, err := os.ReadDir(cfg.SpoolDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name()[0] == '.' {
			continue
		}
		data, err := os.ReadFile(filepath.Join(cfg.SpoolDir, e.Name(), "job.json"))
		if err != nil {
			cfg.Log.Warn("skipping unreadable spool entry", "dir", e.Name(), "err", err)
			continue
		}
		var j Job
		if err := json.Unmarshal(data, &j); err != nil || j.ID != e.Name() {
			cfg.Log.Warn("skipping corrupt spool entry", "dir", e.Name(), "err", err)
			continue
		}
		m.jobs[j.ID] = &j
		if j.MessageID != "" {
			m.byMessageID[j.MessageID] = &j
		}
	}
	return m, nil
}

func (m *Manager) dir(id string) string { return filepath.Join(m.cfg.SpoolDir, id) }

// save persists j. The caller holds m.mu.
func (m *Manager) save(j *Job) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return archive.WriteFileAtomic(filepath.Join(m.dir(j.ID), "job.json"), data)
}

// update applies fn to the job under the lock and persists it.
func (m *Manager) update(j *Job, fn func(*Job)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(j)
	if j.MessageID != "" {
		m.byMessageID[j.MessageID] = j
	}
	if err := m.save(j); err != nil {
		m.cfg.Log.Error("failed to persist job", "job", j.ID, "err", err)
	}
}

func (m *Manager) poke() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// ErrUnknownPartner is returned by Submit for a partner without outbound
// settings.
var ErrUnknownPartner = errors.New("no partner with outbound settings by that AS2 ID")

// Submission is a payload to send to a partner.
type Submission struct {
	Partner       string
	Filename      string // default payload.bin
	ContentType   string // default guessed from Filename
	Subject       string
	CorrelationID string
	Payload       []byte
}

// Submit queues a payload for delivery to a partner over AS2.
func (m *Manager) Submit(s Submission) (Job, error) {
	if _, ok := m.cfg.Partners[s.Partner]; !ok {
		return Job{}, fmt.Errorf("%w: %q", ErrUnknownPartner, s.Partner)
	}
	if s.Filename == "" {
		s.Filename = "payload.bin"
	}
	if s.ContentType == "" {
		s.ContentType = ContentTypeFor(s.Filename)
	}
	j := m.newJob(KindSend, s.Partner, s.Filename, s.ContentType, s.Subject, len(s.Payload))
	j.CorrelationID = s.CorrelationID
	if err := m.enqueue(j, s.Payload, nil); err != nil {
		return Job{}, err
	}
	m.cfg.Log.Info("message queued", "job", j.ID, "partner", s.Partner, "filename", s.Filename,
		"bytes", len(s.Payload), "correlation_id", s.CorrelationID)
	return *j, nil
}

// SubmitForward queues a received payload for the partner's forward
// endpoint. inboundDir is the received message's archive directory; its
// meta.json is kept up to date with the forward's progress.
func (m *Manager) SubmitForward(partner string, msg forward.Message, inboundDir string) (Job, error) {
	if _, ok := m.cfg.Forwards[partner]; !ok {
		return Job{}, fmt.Errorf("partner %q has no queued forward endpoint", partner)
	}
	j := m.newJob(KindForward, partner, msg.Filename, msg.ContentType, msg.Subject, len(msg.Payload))
	j.Inbound = &InboundRef{From: msg.From, To: msg.To, MessageID: msg.MessageID, ArchiveDir: inboundDir}
	// Record the queued state before any worker can pick the job up, so
	// the worker's final record always lands last.
	before := func() error { return m.cfg.Archive.UpdateMeta(inboundDir, "forward", forwardRecord(j)) }
	if err := m.enqueue(j, msg.Payload, before); err != nil {
		return Job{}, err
	}
	m.cfg.Log.Info("forward queued", "job", j.ID, "partner", partner, "message_id", msg.MessageID, "bytes", len(msg.Payload))
	return *j, nil
}

func (m *Manager) newJob(kind, partner, filename, contentType, subject string, size int) *Job {
	now := time.Now().UTC()
	return &Job{
		ID:          now.Format("20060102T150405") + "-" + randHex(6),
		Kind:        kind,
		Partner:     partner,
		Filename:    filename,
		ContentType: contentType,
		Subject:     subject,
		Size:        size,
		Created:     now,
		State:       Pending,
		NextAttempt: now,
	}
}

// enqueue writes a new job to the spool and makes it visible to workers.
// before, if set, runs once the job is durable but before it is visible.
func (m *Manager) enqueue(j *Job, payload []byte, before func() error) error {
	dir := m.dir(j.ID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := archive.WriteFileAtomic(filepath.Join(dir, "payload"), payload); err != nil {
		os.RemoveAll(dir)
		return err
	}
	m.mu.Lock()
	err := m.save(j)
	m.mu.Unlock()
	if err == nil && before != nil {
		err = before()
	}
	if err != nil {
		os.RemoveAll(dir)
		return err
	}
	m.mu.Lock()
	m.jobs[j.ID] = j
	m.mu.Unlock()
	m.poke()
	return nil
}

// forwardRecord is what a received message's meta.json says about its forward.
func forwardRecord(j *Job) map[string]any {
	r := map[string]any{"mode": "queued", "job": j.ID, "state": j.State, "attempts": j.Attempts}
	if j.LastStatus != 0 {
		r["http_status"] = j.LastStatus
	}
	if j.LastError != "" {
		r["error"] = j.LastError
	}
	if !j.Finished.IsZero() {
		r["finished"] = j.Finished
	}
	return r
}

// Wait blocks until the job is delivered or failed, or ctx ends, and
// returns the job's state at that point and whether it is final.
func (m *Manager) Wait(ctx context.Context, id string) (Job, bool) {
	m.mu.Lock()
	j, ok := m.jobs[id]
	if !ok || j.finished() {
		m.mu.Unlock()
		if !ok {
			return Job{}, false
		}
		return m.Get(id)
	}
	ch := make(chan struct{})
	m.waiters[id] = append(m.waiters[id], ch)
	m.mu.Unlock()

	select {
	case <-ch:
	case <-ctx.Done():
		m.mu.Lock()
		m.waiters[id] = slices.DeleteFunc(m.waiters[id], func(c chan struct{}) bool { return c == ch })
		m.mu.Unlock()
	}
	j2, _ := m.Get(id)
	return j2, j2.finished()
}

// Get returns a copy of a job.
func (m *Manager) Get(id string) (Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return Job{}, false
	}
	return *j, true
}

// List returns jobs, newest first, optionally only those in state.
func (m *Manager) List(state State, limit int) []Job {
	m.mu.Lock()
	out := []Job{}
	for _, j := range m.jobs {
		if state == "" || j.State == state {
			out = append(out, *j)
		}
	}
	m.mu.Unlock()
	slices.SortFunc(out, func(a, b Job) int { return b.Created.Compare(a.Created) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Retry requeues a failed job. It is repackaged with a new Message-ID, since
// the partner has already seen (and rejected or never acknowledged) the old one.
func (m *Manager) Retry(id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return Job{}, errors.New("no such job")
	}
	if j.State != Failed {
		return Job{}, fmt.Errorf("job is %s, only failed jobs can be retried", j.State)
	}
	if _, err := os.Stat(filepath.Join(m.dir(id), "payload")); err != nil {
		return Job{}, fmt.Errorf("payload is no longer in the spool: %w", err)
	}
	os.Remove(filepath.Join(m.dir(id), "request.http"))
	os.Remove(filepath.Join(m.dir(id), "mdn.http"))
	delete(m.byMessageID, j.MessageID)
	*j = Job{
		ID: j.ID, Kind: j.Kind, Partner: j.Partner, Filename: j.Filename, ContentType: j.ContentType,
		Subject: j.Subject, CorrelationID: j.CorrelationID, Size: j.Size, Created: j.Created,
		Inbound: j.Inbound, State: Pending, NextAttempt: time.Now().UTC(),
	}
	if err := m.save(j); err != nil {
		return Job{}, err
	}
	m.poke()
	return *j, nil
}

// Run delivers jobs until ctx is canceled, then waits for in-flight sends.
func (m *Manager) Run(ctx context.Context) {
	work := make(chan *Job)
	var wg sync.WaitGroup
	for range max(m.cfg.Workers, 1) {
		wg.Go(func() {
			for j := range work {
				if !m.attempt(ctx, j) {
					m.release(j)
				}
				m.poke()
			}
		})
	}

	if m.cfg.Webhook != nil {
		// Callbacks that never got through before the last shutdown.
		m.mu.Lock()
		for id, j := range m.jobs {
			if j.Kind == KindSend && j.finished() && !j.Notified {
				m.queueNotify(id)
			}
		}
		m.mu.Unlock()
		wg.Go(func() { m.runNotifier(ctx) })
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastCleanup := time.Time{}
	for {
		m.expireAsyncMDNs()
		if time.Since(lastCleanup) > time.Hour {
			m.cleanup()
			lastCleanup = time.Now()
		}
	dispatch:
		for _, j := range m.due() {
			select {
			case work <- j:
			case <-ctx.Done():
				m.release(j)
				break dispatch
			}
		}
		select {
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return
		case <-tick.C:
		case <-m.wake:
		}
	}
}

// due marks and returns the pending jobs whose next attempt has come.
func (m *Manager) due() []*Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var out []*Job
	for _, j := range m.jobs {
		if j.State == Pending && !m.busy[j.ID] && !j.NextAttempt.After(now) {
			m.busy[j.ID] = true
			out = append(out, j)
		}
	}
	slices.SortFunc(out, func(a, b *Job) int { return a.Created.Compare(b.Created) })
	if len(out) > m.cfg.Workers {
		for _, j := range out[m.cfg.Workers:] {
			delete(m.busy, j.ID)
		}
		out = out[:m.cfg.Workers]
	}
	return out
}

// expireAsyncMDNs treats an async MDN that never arrived as a failed attempt.
func (m *Manager) expireAsyncMDNs() {
	m.mu.Lock()
	var expired []*Job
	for _, j := range m.jobs {
		if j.State == AwaitingMDN && !m.busy[j.ID] && time.Now().After(j.MDNDeadline) {
			m.busy[j.ID] = true
			expired = append(expired, j)
		}
	}
	m.mu.Unlock()
	for _, j := range expired {
		m.retryLater(j, errors.New("no asynchronous MDN received in time"))
		m.release(j)
	}
}

// cleanup removes finished jobs past the retention period. Their archived
// copies remain.
func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-m.cfg.Retention)
	for id, j := range m.jobs {
		if (j.State == Delivered || j.State == Failed) && j.Finished.Before(cutoff) {
			if err := os.RemoveAll(m.dir(id)); err != nil {
				m.cfg.Log.Warn("failed to remove spool entry", "job", id, "err", err)
				continue
			}
			delete(m.jobs, id)
			delete(m.byMessageID, j.MessageID)
		}
	}
}

// attempt makes one delivery attempt. It reports whether it already released
// the job (handing it to whoever delivers the async MDN).
func (m *Manager) attempt(ctx context.Context, j *Job) (released bool) {
	if j.Kind == KindForward {
		m.attemptForward(ctx, j)
		return false
	}
	log := m.cfg.Log.With("job", j.ID, "partner", j.Partner)
	p, ok := m.cfg.Partners[j.Partner]
	if !ok {
		m.finish(j, Failed, "partner no longer has outbound settings", nil)
		return false
	}
	header, body, err := m.packaged(j, p)
	if err != nil {
		m.finish(j, Failed, "packaging failed: "+err.Error(), nil)
		return false
	}

	m.update(j, func(j *Job) {
		j.Attempts++
		j.LastAttempt = time.Now().UTC()
	})
	log.Info("sending", "message_id", j.MessageID, "attempt", j.Attempts, "url", p.URL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(body))
	if err != nil {
		m.finish(j, Failed, err.Error(), nil)
		return false
	}
	req.Header = header
	resp, err := m.cfg.Client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			// Shutting down: the attempt does not count.
			m.update(j, func(j *Job) { j.Attempts-- })
			return false
		}
		m.retryLater(j, err)
		return false
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	resp.Body.Close()
	if err != nil {
		m.retryLater(j, fmt.Errorf("reading response: %w", err))
		return false
	}

	switch code := resp.StatusCode; {
	case code >= 500, code == http.StatusRequestTimeout, code == http.StatusTooManyRequests:
		m.retryLater(j, fmt.Errorf("partner responded %s", resp.Status))
		return false
	case code/100 != 2:
		m.finish(j, Failed, fmt.Sprintf("partner rejected the message: %s %s", resp.Status, firstLine(respBody)), nil)
		return false
	}

	switch {
	case !p.Options.RequestMDN:
		m.finish(j, Delivered, "", nil)
	case p.Options.AsyncMDNURL != "":
		// Release the job in the same step, since a fast partner's MDN can
		// arrive before this function returns. One that arrived even before
		// the partner answered the POST was held for us.
		var early *earlyMDN
		m.update(j, func(j *Job) {
			j.State = AwaitingMDN
			j.MDNDeadline = time.Now().UTC().Add(m.cfg.MDNTimeout)
			if e, ok := m.early[j.ID]; ok {
				early = &e
				delete(m.early, j.ID)
			} else {
				delete(m.busy, j.ID)
			}
		})
		if early != nil {
			m.applyMDN(j, p, early.header, early.body)
			return false
		}
		log.Info("sent; awaiting asynchronous MDN", "message_id", j.MessageID)
		return true
	default:
		m.applyMDN(j, p, resp.Header, respBody)
	}
	return false
}

// attemptForward posts a received payload to the partner's forward endpoint.
func (m *Manager) attemptForward(ctx context.Context, j *Job) {
	target, ok := m.cfg.Forwards[j.Partner]
	if !ok {
		m.finish(j, Failed, "partner no longer has a queued forward endpoint", nil)
		return
	}
	payload, err := os.ReadFile(filepath.Join(m.dir(j.ID), "payload"))
	if err != nil {
		m.finish(j, Failed, "payload missing from spool: "+err.Error(), nil)
		return
	}
	m.update(j, func(j *Job) {
		j.Attempts++
		j.LastAttempt = time.Now().UTC()
	})
	status, err := target.Send(ctx, forward.Message{
		From: j.Inbound.From, To: j.Inbound.To, MessageID: j.Inbound.MessageID,
		Filename: j.Filename, Subject: j.Subject, ContentType: j.ContentType, Payload: payload,
	})
	m.update(j, func(j *Job) { j.LastStatus = status })
	switch fe, _ := errors.AsType[*forward.Error](err); {
	case err == nil:
		m.finish(j, Delivered, "", nil)
	case ctx.Err() != nil:
		m.update(j, func(j *Job) { j.Attempts-- }) // shutting down; does not count
	case fe != nil && !fe.Retryable:
		m.finish(j, Failed, err.Error(), nil)
	default:
		m.retryLater(j, err)
	}
}

// queueNotify schedules a webhook callback for a finished send.
func (m *Manager) queueNotify(id string) {
	select {
	case m.notify <- id:
	default:
		m.cfg.Log.Warn("webhook backlog full; callback will be sent after the next restart", "job", id)
	}
}

// runNotifier delivers webhook callbacks until ctx ends.
func (m *Manager) runNotifier(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-m.notify:
			wg.Go(func() { m.deliverNotification(ctx, id) })
		}
	}
}

func (m *Manager) deliverNotification(ctx context.Context, id string) {
	var err error
	for _, delay := range m.cfg.WebhookDelays {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return // Notified stays false, so it is resent after a restart
		}
		j, ok := m.Get(id)
		if !ok || j.Notified {
			return
		}
		if err = m.cfg.Webhook.Post(ctx, j.Status()); err == nil {
			m.mu.Lock()
			if live := m.jobs[id]; live != nil {
				live.Notified = true
				m.save(live)
			}
			m.mu.Unlock()
			m.cfg.Log.Info("status webhook notified", "job", id, "state", j.State, "correlation_id", j.CorrelationID)
			return
		}
		if fe, ok := errors.AsType[*forward.Error](err); ok && !fe.Retryable {
			break
		}
		m.cfg.Log.Warn("status webhook failed; will retry", "job", id, "err", err)
	}
	m.cfg.Log.Error("giving up on status webhook", "job", id, "err", err)
}

// packaged returns the job's AS2 message, building and persisting it on the
// first attempt so that retries resend the same Message-ID and bytes.
func (m *Manager) packaged(j *Job, p *Partner) (http.Header, []byte, error) {
	path := filepath.Join(m.dir(j.ID), "request.http")
	if raw, err := os.ReadFile(path); err == nil && j.Sent != nil {
		return parseRequest(raw)
	}
	payload, err := os.ReadFile(filepath.Join(m.dir(j.ID), "payload"))
	if err != nil {
		return nil, nil, err
	}
	opts := p.Options
	opts.Filename, opts.ContentType, opts.Subject = j.Filename, j.ContentType, j.Subject
	out, err := m.cfg.Local.Package(p.Partner, payload, opts)
	if err != nil {
		return nil, nil, err
	}
	if err := archive.WriteFileAtomic(path, out.Bytes()); err != nil {
		return nil, nil, err
	}
	m.update(j, func(j *Job) {
		j.MessageID = out.MessageID
		j.Sent = &out.Sent
	})
	return out.Header, out.Body, nil
}

func parseRequest(raw []byte) (http.Header, []byte, error) {
	r := bufio.NewReader(bytes.NewReader(raw))
	h, err := textproto.NewReader(r).ReadMIMEHeader()
	if err != nil {
		return nil, nil, fmt.Errorf("spooled request: %w", err)
	}
	body, err := io.ReadAll(r)
	return http.Header(h), body, err
}

// applyMDN records a partner's MDN for j and finishes the job.
func (m *Manager) applyMDN(j *Job, p *Partner, h http.Header, body []byte) {
	var raw bytes.Buffer
	h.Write(&raw)
	raw.WriteString("\r\n")
	raw.Write(body)
	if err := archive.WriteFileAtomic(filepath.Join(m.dir(j.ID), "mdn.http"), raw.Bytes()); err != nil {
		m.cfg.Log.Error("failed to store MDN", "job", j.ID, "err", err)
	}

	rc, err := as2.ParseMDN(p.Partner, h, body)
	if err == nil {
		err = rc.Match(*j.Sent)
	}
	if err != nil {
		// The partner may well have the message; resending the same
		// Message-ID lets it recognize the duplicate.
		m.retryLater(j, fmt.Errorf("unusable MDN: %w", err))
		return
	}
	m.update(j, func(j *Job) {
		j.Disposition = rc.Disposition
		j.MDNMessageID = rc.MessageID
		j.MIC = rc.MIC + ", " + rc.MICAlg
	})
	switch {
	case !rc.Processed:
		m.finish(j, Failed, "partner reported "+rc.Disposition, rc)
	case !rc.MICMatches:
		m.finish(j, Failed, "MIC in MDN does not match the message sent", rc)
	default:
		m.finish(j, Delivered, "", rc)
	}
}

// HandleMDN accepts an asynchronous MDN posted to the inbound endpoint.
func (m *Manager) HandleMDN(h http.Header, body []byte) error {
	from := as2.UnquoteID(h.Get("As2-From"))
	p, ok := m.cfg.Partners[from]
	if !ok {
		return fmt.Errorf("MDN from unknown partner %q", from)
	}
	rc, err := as2.ParseMDN(p.Partner, h, body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	j, ok := m.byMessageID[rc.OriginalMessageID]
	if !ok || j.Partner != from {
		m.mu.Unlock()
		return fmt.Errorf("MDN for unknown message %s", rc.OriginalMessageID)
	}
	if j.State == Delivered || j.State == Failed {
		m.mu.Unlock()
		m.cfg.Log.Info("ignoring MDN for finished job", "job", j.ID, "message_id", j.MessageID)
		return nil
	}
	if m.busy[j.ID] {
		// Still being sent: hold the MDN for the worker to apply.
		m.early[j.ID] = earlyMDN{h.Clone(), body}
		m.mu.Unlock()
		return nil
	}
	m.busy[j.ID] = true
	m.mu.Unlock()
	defer m.release(j)

	// A pending job here is one whose MDN timed out and that is due to be
	// resent; the late MDN still settles it.
	m.applyMDN(j, p, h, body)
	return nil
}

func (m *Manager) release(j *Job) {
	m.mu.Lock()
	delete(m.busy, j.ID)
	delete(m.early, j.ID)
	m.mu.Unlock()
}

// retryLater schedules another attempt, or fails the job once attempts run out.
func (m *Manager) retryLater(j *Job, cause error) {
	if j.Attempts >= m.cfg.MaxAttempts {
		attempts := "attempts"
		if j.Attempts == 1 {
			attempts = "attempt"
		}
		m.finish(j, Failed, fmt.Sprintf("giving up after %d %s: %v", j.Attempts, attempts, cause), nil)
		return
	}
	delay := m.cfg.Backoff(max(j.Attempts, 1))
	m.update(j, func(j *Job) {
		j.State = Pending
		j.LastError = cause.Error()
		j.NextAttempt = time.Now().UTC().Add(delay)
	})
	what := "delivery attempt failed; will retry"
	if j.Kind == KindForward {
		what = "forward attempt failed; will retry"
	}
	m.cfg.Log.Warn(what, "job", j.ID, "partner", j.Partner,
		"attempt", j.Attempts, "retry_in", delay, "err", cause)
}

// finish moves j to a final state, records it, and wakes anyone waiting.
// Delivered jobs drop their spooled payload; failed ones keep it for a
// manual retry.
func (m *Manager) finish(j *Job, state State, reason string, rc *as2.Receipt) {
	if j.Kind == KindForward {
		m.finishForward(j, state, reason)
	} else {
		m.finishSend(j, state, reason, rc)
		if m.cfg.Webhook != nil {
			m.queueNotify(j.ID)
		}
	}
	m.mu.Lock()
	for _, ch := range m.waiters[j.ID] {
		close(ch)
	}
	delete(m.waiters, j.ID)
	m.mu.Unlock()
}

// finishForward records the outcome in the received message's meta.json.
// The message itself is already archived.
func (m *Manager) finishForward(j *Job, state State, reason string) {
	m.update(j, func(j *Job) {
		j.State, j.LastError, j.Finished = state, reason, time.Now().UTC()
	})
	m.mu.Lock()
	rec := forwardRecord(j)
	m.mu.Unlock()
	if err := m.cfg.Archive.UpdateMeta(j.Inbound.ArchiveDir, "forward", rec); err != nil {
		m.cfg.Log.Error("failed to record forward result in meta.json", "job", j.ID, "err", err)
	}
	if state == Delivered {
		os.Remove(filepath.Join(m.dir(j.ID), "payload"))
		m.cfg.Log.Info("forwarded", "job", j.ID, "partner", j.Partner, "message_id", j.Inbound.MessageID,
			"attempts", j.Attempts, "http_status", j.LastStatus)
	} else {
		m.cfg.Log.Error("forward failed", "job", j.ID, "partner", j.Partner, "message_id", j.Inbound.MessageID,
			"attempts", j.Attempts, "err", reason)
	}
}

// finishSend archives a send to a partner.
func (m *Manager) finishSend(j *Job, state State, reason string, rc *as2.Receipt) {
	// Archive first, so a job never shows as finished before it is archived.
	m.mu.Lock()
	final := *j
	m.mu.Unlock()
	final.State, final.LastError, final.Finished = state, reason, time.Now().UTC()

	dir := m.dir(j.ID)
	files := map[string][]byte{}
	for spooled, archived := range map[string]string{
		"payload":      "payload/" + archive.SafeName(j.Filename),
		"request.http": "request.http",
		"mdn.http":     "mdn.http",
	} {
		if b, err := os.ReadFile(filepath.Join(dir, spooled)); err == nil {
			files[archived] = b
		}
	}
	files["meta.json"], _ = json.MarshalIndent(final, "", "  ")
	archived, err := m.cfg.Archive.Save("outbound", j.Partner, or(j.MessageID, j.ID), j.Created, files)
	if err != nil {
		m.cfg.Log.Error("failed to archive outbound message", "job", j.ID, "err", err)
	}
	m.update(j, func(j *Job) {
		j.State, j.LastError, j.Finished = final.State, final.LastError, final.Finished
		j.ArchiveDir = archived
	})
	if err == nil && state == Delivered {
		os.Remove(filepath.Join(dir, "payload"))
		os.Remove(filepath.Join(dir, "request.http"))
	}

	attrs := []any{"job", j.ID, "partner", j.Partner, "message_id", j.MessageID, "attempts", j.Attempts, "archive", archived}
	if rc != nil {
		attrs = append(attrs, "disposition", rc.Disposition)
	}
	if state == Delivered {
		m.cfg.Log.Info("message delivered", attrs...)
	} else {
		m.cfg.Log.Error("message failed", append(attrs, "err", reason)...)
	}
}

func firstLine(b []byte) string {
	line, _, _ := bytes.Cut(bytes.TrimSpace(b), []byte("\n"))
	if len(line) > 200 {
		line = line[:200]
	}
	return string(line)
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
