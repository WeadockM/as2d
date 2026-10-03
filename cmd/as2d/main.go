// Command as2d is an AS2 (RFC 4130) daemon. It receives messages from
// partners and, for partners with outbound settings, queues and sends
// messages to them.
package main

import (
	"context"
	"crypto/x509"
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

	"github.com/WeadockM/as2d/internal/accounts"
	"github.com/WeadockM/as2d/internal/archive"
	"github.com/WeadockM/as2d/internal/as2"
	"github.com/WeadockM/as2d/internal/cli"
	"github.com/WeadockM/as2d/internal/config"
	"github.com/WeadockM/as2d/internal/forward"
	"github.com/WeadockM/as2d/internal/index"
	"github.com/WeadockM/as2d/internal/outbound"
	"github.com/WeadockM/as2d/internal/server"
	"github.com/WeadockM/as2d/internal/version"
	"github.com/WeadockM/as2d/internal/web"
)

func main() {
	configPath := flag.String("config", cli.DefaultConfigPath(), "path to the configuration file")
	reindex := flag.Bool("reindex", false, "rebuild the message index from the archive, then exit")
	createAdmin := flag.String("create-admin", "", "create a dashboard admin with this username, print a one-time password, then exit")
	resetPassword := flag.String("reset-password", "", "give this dashboard user a new one-time password, then exit")
	generatePepper := flag.Bool("generate-pepper", false, "print a new random password pepper, then exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	switch {
	case *showVersion:
		fmt.Println("as2d", version.String())
		return
	case *generatePepper:
		fmt.Println(accounts.GeneratePepper())
		return
	case *createAdmin != "" || *resetPassword != "":
		if err := accountCommand(*configPath, *createAdmin, *resetPassword); err != nil {
			fmt.Fprintln(os.Stderr, "as2d:", err)
			cli.Hold()
			os.Exit(1)
		}
		cli.Hold()
		return
	}

	// systemd's journal records timestamps, and stderr is where it reads from.
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*configPath, *reindex, log); err != nil {
		log.Error("fatal", "err", err)
		cli.Explain("as2d", `-config path\to\config.json`,
			"To start it by double-clicking instead, put a working config.json next to as2d.exe.")
		cli.Hold()
		os.Exit(1)
	}
}

func run(configPath string, reindexOnly bool, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.ArchiveDir == "" {
		return fmt.Errorf("%s: archive_dir is required", configPath)
	}
	if err := os.MkdirAll(cfg.ArchiveDir, 0o750); err != nil {
		return err
	}
	idx, err := openIndex(cfg, reindexOnly, log)
	if err != nil || reindexOnly {
		return err
	}
	defer idx.Close()

	local, partners, err := cfg.Stations()
	if err != nil {
		return err
	}
	warnCertificates(cfg, local, partners, log)
	store := &archive.Store{Root: cfg.ArchiveDir, Index: idx, OnIndexError: func(dir string, err error) {
		log.Error("failed to index archived message; run as2d -reindex to repair", "dir", dir, "err", err)
	}}

	users, err := openAccounts(cfg)
	if err != nil {
		return err
	}
	if users != nil {
		defer users.Store.Close()
		n, _ := users.Store.CountUsers()
		if n == 0 {
			log.Warn("user accounts are configured but none exist yet; until then the dashboard signs in with api_token. Create the first admin with: as2d -create-admin <username>")
		} else {
			log.Info("user accounts enabled", "users", n, "db", cfg.StateDB())
		}
	}

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

	var mgr *outbound.Manager
	if cfg.NeedsQueue() {
		if mgr, err = newOutbound(cfg, local, partners, store, queued, log); err != nil {
			return err
		}
		srv.MDNs = mgr
		srv.Queue = mgr
		background.Go(func() { mgr.Run(outCtx) })
		if cfg.OutboxDir != "" {
			background.Go(func() { mgr.WatchOutbox(outCtx, cfg.OutboxDir, 2*time.Second) })
		}
	}

	// The API listener serves the dashboard, archive and partner views, and
	// the outbound API when there is a queue.
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
		var webPartners []web.Partner
		for i := range cfg.Partners {
			p := &cfg.Partners[i]
			webPartners = append(webPartners, web.Partner{Config: p, Cert: partners[p.AS2ID].Cert})
		}
		h := web.Handler(web.Config{
			Index: idx, Queue: mgr, Local: local, Partners: webPartners,
			Token: cfg.APIToken, Accounts: users, Secure: cfg.APITLSCert != "", MaxBody: cfg.MaxBodyBytes, Log: log.With("component", "web"),
		})
		// The write timeout must outlast the longest wait= a caller can ask for.
		serve("api", cfg.APIListen, h, cfg.APITLSCert, cfg.APITLSKey, outbound.MaxWait+time.Minute)
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.Path, srv)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	serve("as2", cfg.Listen, mux, cfg.TLSCert, cfg.TLSKey, 5*time.Minute)
	log.Info("started", "version", version.String(), "local", cfg.Local.AS2ID, "partners", len(cfg.Partners), "path", cfg.Path,
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

// openAccounts opens the user account database, if accounts are configured.
func openAccounts(cfg *config.Config) (*accounts.Service, error) {
	if cfg.PasswordPepperFile == "" {
		return nil, nil
	}
	peppers, err := accounts.LoadPeppers(cfg.PasswordPepperFile, cfg.PreviousPepperFiles)
	if err != nil {
		return nil, err
	}
	store, err := accounts.Open(cfg.StateDB())
	if err != nil {
		return nil, err
	}
	return accounts.NewService(store, peppers), nil
}

// accountCommand runs -create-admin or -reset-password and prints the
// one-time password.
func accountCommand(configPath, createAdmin, resetPassword string) error {
	if os.Geteuid() == 0 {
		return errors.New("don't run this as root: the account database must stay owned by the daemon's user. " +
			"Run it as that user instead, e.g. sudo -u as2d as2d -config " + configPath + " ...")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.PasswordPepperFile == "" {
		return errors.New("user accounts are not configured: set password_pepper_file and state_dir in " + configPath)
	}
	svc, err := openAccounts(cfg)
	if err != nil {
		return err
	}
	defer svc.Store.Close()

	var name, temp string
	if createAdmin != "" {
		name = createAdmin
		temp, err = svc.CreateUser("cli", createAdmin, accounts.Admin, "")
		if err == nil {
			fmt.Printf("Created admin %q.\n", name)
		}
	} else {
		name = resetPassword
		temp, err = svc.ResetPassword("cli", resetPassword, "")
		if err == nil {
			fmt.Printf("Reset the password for %q and signed them out everywhere.\n", name)
		}
	}
	if err != nil {
		return err
	}
	fmt.Printf("One-time password: %s\n\n", temp)
	fmt.Printf("Sign in to the dashboard as %s with it; you will be asked to choose a new password.\n", name)
	return nil
}

// openIndex opens the message index, rebuilding it from the archive when it
// is new or its format changed, or when asked to.
func openIndex(cfg *config.Config, rebuild bool, log *slog.Logger) (*index.DB, error) {
	idx, fresh, err := index.Open(cfg.IndexDB, cfg.ArchiveDir)
	if err != nil {
		return nil, err
	}
	if fresh || rebuild {
		start := time.Now()
		n, err := idx.Reindex()
		if err != nil {
			idx.Close()
			return nil, fmt.Errorf("rebuilding the index: %w", err)
		}
		log.Info("index rebuilt from the archive", "messages", n, "db", cfg.IndexDB, "took", time.Since(start).Round(time.Millisecond))
	}
	if rebuild {
		return nil, idx.Close()
	}
	return idx, nil
}

// warnCertificates logs certificates that have expired or expire soon.
func warnCertificates(cfg *config.Config, local as2.Station, partners map[string]*as2.Partner, log *slog.Logger) {
	check := func(owner string, c *x509.Certificate) {
		switch web.CertStatus(c, time.Now()) {
		case "expired":
			log.Error("certificate has expired or is not yet valid", "owner", owner, "not_after", c.NotAfter)
		case "expiring":
			log.Warn("certificate expires soon", "owner", owner, "not_after", c.NotAfter,
				"days_left", int(time.Until(c.NotAfter).Hours()/24))
		}
	}
	check("local station "+local.ID, local.Cert)
	for _, p := range cfg.Partners {
		check("partner "+p.AS2ID, partners[p.AS2ID].Cert)
	}
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
