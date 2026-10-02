// Command as2d is an AS2 (RFC 4130) daemon. It receives messages from
// partners and, for partners with outbound settings, queues and sends
// messages to them.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/config"
	"github.com/WeadockM/as2d/internal/forward"
	"github.com/WeadockM/as2d/internal/outbound"
	"github.com/WeadockM/as2d/internal/server"
)

func main() {
	configPath := flag.String("config", "/etc/as2d/config.json", "path to the configuration file")
	flag.Parse()

	// systemd's journal records timestamps, and stderr is where it reads from.
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*configPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.ArchiveDir == "" {
		return fmt.Errorf("%s: archive_dir is required", configPath)
	}
	local, partners, err := cfg.Stations()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.ArchiveDir, 0o750); err != nil {
		return err
	}
	store := &archive.Store{Root: cfg.ArchiveDir}

	srv := server.New(&as2.Receiver{Local: local, Partners: partners}, store, log, cfg.MaxBodyBytes)
	srv.InboxDir = cfg.InboxDir

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Outbound work stops only after the HTTP servers have drained, so
	// in-flight async MDNs can still settle their jobs.
	outCtx, stopOutbound := context.WithCancel(context.Background())
	defer stopOutbound()
	var background sync.WaitGroup

	var servers []*http.Server
	errc := make(chan error, 3)
	serve := func(name, addr string, h http.Handler, tlsCert, tlsKey string, writeTimeout time.Duration) {
		hs := &http.Server{
			Addr:              addr,
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       5 * time.Minute,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		}
		servers = append(servers, hs)
		go func() {
			log.Info("listening", "server", name, "addr", addr, "tls", tlsCert != "")
			var err error
			if tlsCert != "" {
				err = hs.ListenAndServeTLS(tlsCert, tlsKey)
			} else {
				err = hs.ListenAndServe()
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s server: %w", name, err)
			}
		}()
	}

	forwards, queued, err := newForwards(cfg)
	if err != nil {
		return err
	}
	srv.Forwards = forwards

	if cfg.NeedsQueue() {
		mgr, err := newOutbound(cfg, local, partners, store, queued, log)
		if err != nil {
			return err
		}
		srv.MDNs = mgr
		srv.Queue = mgr
		background.Go(func() { mgr.Run(outCtx) })
		if cfg.OutboxDir != "" {
			background.Go(func() { mgr.WatchOutbox(outCtx, cfg.OutboxDir, 2*time.Second) })
		}
		if cfg.APIListen != "" {
			host, _, _ := net.SplitHostPort(cfg.APIListen)
			if !isLoopback(host) {
				if cfg.APIToken == "" {
					return fmt.Errorf("api_listen %s is not a loopback address; set api_token", cfg.APIListen)
				}
				if cfg.APITLSCert == "" {
					log.Warn("the API is reachable from the network without TLS; the token travels in clear text",
						"api_listen", cfg.APIListen)
				}
			}
			// The write timeout must outlast the longest wait= a caller can ask for.
			serve("api", cfg.APIListen, mgr.APIHandler(cfg.APIToken, cfg.MaxBodyBytes),
				cfg.APITLSCert, cfg.APITLSKey, outbound.MaxWait+time.Minute)
		}
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.Path, srv)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	serve("as2", cfg.Listen, mux, cfg.TLSCert, cfg.TLSKey, 5*time.Minute)
	log.Info("started", "local", cfg.Local.AS2ID, "partners", len(cfg.Partners), "path", cfg.Path,
		"inbox", cfg.InboxDir, "outbox", cfg.OutboxDir)

	var runErr error
	select {
	case runErr = <-errc:
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var errs []error
	for _, hs := range servers {
		errs = append(errs, hs.Shutdown(sctx))
	}
	errs = append(errs, srv.Shutdown(sctx))
	stopOutbound()
	background.Wait()
	return errors.Join(append(errs, runErr)...)
}

// newForwards builds each partner's forward endpoint. It returns the rules
// for the inbound server and, separately, the targets of queued forwards.
func newForwards(cfg *config.Config) (map[string]*server.ForwardRule, map[string]*forward.Target, error) {
	rules := map[string]*server.ForwardRule{}
	queued := map[string]*forward.Target{}
	for _, p := range cfg.Partners {
		f := p.Forward
		if f == nil {
			continue
		}
		client, err := forward.NewClient(f.CAFile, f.Timeout.Duration)
		if err != nil {
			return nil, nil, fmt.Errorf("partner %q forward: %w", p.AS2ID, err)
		}
		password, err := forward.ReadSecret(f.PasswordFile)
		if err != nil {
			return nil, nil, fmt.Errorf("partner %q forward: %w", p.AS2ID, err)
		}
		t := &forward.Target{URL: f.URL, Username: f.Username, Password: password, Client: client}
		rules[p.AS2ID] = &server.ForwardRule{Target: t, BeforeMDN: f.Mode == config.ForwardBeforeMDN}
		if f.Mode == config.ForwardQueued {
			queued[p.AS2ID] = t
		}
	}
	return rules, queued, nil
}

func newWebhook(w *config.Webhook) (*forward.Webhook, error) {
	if w == nil {
		return nil, nil
	}
	client, err := forward.NewClient(w.CAFile, w.Timeout.Duration)
	if err != nil {
		return nil, fmt.Errorf("status_webhook: %w", err)
	}
	password, err := forward.ReadSecret(w.PasswordFile)
	if err != nil {
		return nil, fmt.Errorf("status_webhook: %w", err)
	}
	token, err := forward.ReadSecret(w.BearerTokenFile)
	if err != nil {
		return nil, fmt.Errorf("status_webhook: %w", err)
	}
	return &forward.Webhook{URL: w.URL, Username: w.Username, Password: password, BearerToken: token, Client: client}, nil
}

func newOutbound(cfg *config.Config, local as2.Station, partners map[string]*as2.Partner,
	store *archive.Store, forwards map[string]*forward.Target, log *slog.Logger) (*outbound.Manager, error) {
	if cfg.SpoolDir == "" {
		return nil, errors.New("spool_dir is required to send to partners or to forward in queued mode")
	}
	webhook, err := newWebhook(cfg.StatusWebhook)
	if err != nil {
		return nil, err
	}
	out := map[string]*outbound.Partner{}
	for _, p := range cfg.Partners {
		if p.Outbound == nil {
			continue
		}
		opts := p.Outbound.SendOptions(cfg.PublicURL)
		if p.Outbound.MDN == "async" && opts.AsyncMDNURL == "" {
			return nil, fmt.Errorf("partner %q: async MDNs need public_url or async_mdn_url", p.AS2ID)
		}
		out[p.AS2ID] = &outbound.Partner{Partner: partners[p.AS2ID], URL: p.Outbound.URL, Options: opts}
	}
	return outbound.New(outbound.Config{
		Local:       local,
		Partners:    out,
		SpoolDir:    cfg.SpoolDir,
		Archive:     store,
		Log:         log.With("component", "outbound"),
		Workers:     cfg.Workers,
		MaxAttempts: cfg.MaxAttempts,
		MDNTimeout:  cfg.AsyncMDNTimeout.Duration,
		Retention:   cfg.SpoolRetention.Duration,
		Forwards:    forwards,
		Webhook:     webhook,
	})
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
