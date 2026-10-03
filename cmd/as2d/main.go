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
	"path/filepath"
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
	"github.com/WeadockM/as2d/internal/partners"
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

	local, _, err := cfg.Stations()
	if err != nil {
		return err
	}
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

	srv := server.New(&as2.Receiver{Local: local}, store, log, cfg.MaxBodyBytes)
	srv.InboxDir = cfg.InboxDir

	// The outbound queue exists whenever spool_dir is set, so partners
	// added in the dashboard can be sent to without a restart.
	var mgr *outbound.Manager
	if cfg.SpoolDir != "" {
		if mgr, err = newOutbound(cfg, local, store, log); err != nil {
			return err
		}
		srv.MDNs = mgr
		srv.Queue = mgr
	} else if cfg.NeedsQueue() {
		return errors.New("spool_dir is required to send to partners or to forward in queued mode")
	}

	// Partners from config.json and the dashboard, applied to the receiver,
	// the forward rules and the queue, and replaced live on every change.
	var partnerStore *partners.Store
	if cfg.StateDir != "" {
		if partnerStore, err = partners.OpenStore(filepath.Join(cfg.StateDir, "partners")); err != nil {
			return err
		}
	}
	rt := &partners.Runtime{Sys: cfg, Store: partnerStore, Receiver: srv.Receiver, Server: srv, Manager: mgr,
		Log: log.With("component", "partners")}
	if err := rt.Load(cfg.Partners); err != nil {
		return err
	}
	warnCertificates(local, rt.Current(), log)
	log.Info("partners loaded", "partners", len(rt.Current().Entries), "dashboard_editing", rt.Editable())

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

	if mgr != nil {
		background.Go(func() { mgr.Run(outCtx) })
		if cfg.OutboxDir != "" {
			background.Go(func() { mgr.WatchOutbox(outCtx, cfg.OutboxDir, 2*time.Second) })
		}
	}

	// SIGHUP (systemctl reload as2d) re-reads the partners in config.json.
	// Other config.json changes need a restart.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for range hup {
			fresh, err := config.Load(configPath)
			if err == nil {
				err = rt.Load(fresh.Partners)
			}
			if err != nil {
				log.Error("reloading partners from config.json failed; keeping the current ones", "err", err)
				continue
			}
			log.Info("reloaded partners from config.json; other settings need a restart", "partners", len(rt.Current().Entries))
		}
	}()

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
		h := web.Handler(web.Config{
			Index: idx, Queue: mgr, Local: local, Partners: rt,
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
func warnCertificates(local as2.Station, set *partners.Set, log *slog.Logger) {
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
	for _, e := range set.Entries {
		check("partner "+e.Config.AS2ID, e.Cert)
	}
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

// newOutbound creates the outbound queue. Its partners and forward
// endpoints are set by the partners runtime.
func newOutbound(cfg *config.Config, local as2.Station, store *archive.Store, log *slog.Logger) (*outbound.Manager, error) {
	webhook, err := newWebhook(cfg.StatusWebhook)
	if err != nil {
		return nil, err
	}
	return outbound.New(outbound.Config{
		Local:       local,
		SpoolDir:    cfg.SpoolDir,
		Archive:     store,
		Log:         log.With("component", "outbound"),
		Workers:     cfg.Workers,
		MaxAttempts: cfg.MaxAttempts,
		MDNTimeout:  cfg.AsyncMDNTimeout.Duration,
		Retention:   cfg.SpoolRetention.Duration,
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
