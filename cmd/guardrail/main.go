// Command guardrail runs the Jev Guardrail decision API.
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
	"syscall"
	"time"

	"github.com/alpkeskin/jev-guardrail/internal/api"
	"github.com/alpkeskin/jev-guardrail/internal/auth"
	"github.com/alpkeskin/jev-guardrail/internal/config"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
	"github.com/alpkeskin/jev-guardrail/internal/jev"
	"github.com/alpkeskin/jev-guardrail/internal/logging"
	"github.com/alpkeskin/jev-guardrail/internal/metrics"
	"github.com/alpkeskin/jev-guardrail/internal/policy"
	"github.com/alpkeskin/jev-guardrail/internal/resilience"
)

// Set at build time via -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("guardrail %s (%s)\n", version, commit)
		return
	}
	if err := run(); err != nil {
		slog.Error("guardrail exited", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run() error {
	// Register before anything else so an early SIGTERM is never lost
	// (the default action would kill the process without draining).
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	cfg, err := config.Load(nil)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger, err := logging.New(os.Stdout, cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	logger.Info("starting guardrail", slog.String("version", version), slog.String("commit", commit))

	m := metrics.New(version, commit)

	// Startup fails if default.yaml (or any policy) is missing or invalid.
	store, err := policy.Load(cfg.PolicyDir)
	if err != nil {
		return fmt.Errorf("load policies: %w", err)
	}
	m.SetPoliciesLoaded(len(store.ClientIDs()))
	logger.Info("policies loaded", slog.String("dir", cfg.PolicyDir), slog.Any("client_ids", store.ClientIDs()))

	var authn auth.Authenticator = auth.Disabled{}
	if cfg.AuthDisabled {
		logger.Warn("authentication is disabled (GUARDRAIL_AUTH_DISABLED=true)")
	} else {
		keys, err := auth.ParseStaticKeys(cfg.APIKeys)
		if err != nil {
			return fmt.Errorf("configure authentication: %w", err)
		}
		authn = keys
	}

	evaluator, err := newJevEvaluator(cfg, logger, m)
	if err != nil {
		return err
	}
	logger.Info("jev configured", slog.String("url", cfg.JevURL), slog.String("model", cfg.JevModel))
	service := guardrail.NewService(evaluator, guardrail.ThresholdEngine{}, guardrail.WithObserver(m))

	checks := []api.ReadinessCheck{
		{Name: "policies", Check: func(context.Context) error { return nil }}, // loaded and validated at startup
	}
	if cfg.ReadyCheckJev {
		checks = append(checks, api.ReadinessCheck{Name: "jev", Check: service.Ready})
	}
	handler := api.NewHandler(service, cfg.MaxBodyBytes, checks)

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: api.NewRouter(api.RouterConfig{
			Logger:        logger,
			Handler:       handler,
			Authenticator: authn,
			Resolver:      store,
			Observer:      m,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      cfg.JevTimeout + cfg.JevQueueTimeout + 15*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	servers := []*http.Server{srv}
	if cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", m.Handler())
		servers = append(servers, &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      30 * time.Second,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		})
	}

	// Bind every listener before serving any, so a port conflict fails
	// fast instead of leaving a half-started process.
	var lc net.ListenConfig
	listeners := make([]net.Listener, 0, len(servers))
	for _, s := range servers {
		ln, err := lc.Listen(context.Background(), "tcp", s.Addr)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return fmt.Errorf("listen on %s: %w", s.Addr, err)
		}
		listeners = append(listeners, ln)
	}
	errCh := make(chan error, len(servers))
	for i, s := range servers {
		logger.Info("listening", slog.String("addr", listeners[i].Addr().String()))
		go func(s *http.Server, ln net.Listener) {
			if err := s.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("server %s: %w", s.Addr, err)
			}
		}(s, listeners[i])
	}

	select {
	case err := <-errCh:
		return errors.Join(err, shutdown(logger, servers, cfg.ShutdownTimeout))
	case sig := <-sigCh:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))
	}

	// Graceful shutdown: fail readiness first so load balancers and
	// Kubernetes endpoints stop sending traffic, keep serving during the
	// delay, then stop accepting connections and drain in-flight requests.
	handler.SetDraining()
	m.SetDraining()
	if cfg.ShutdownDelay > 0 {
		logger.Info("draining before shutdown", slog.Duration("delay", cfg.ShutdownDelay))
		select {
		case <-time.After(cfg.ShutdownDelay):
		case <-sigCh:
			logger.Warn("second signal received, skipping drain delay")
		}
	}
	return shutdown(logger, servers, cfg.ShutdownTimeout)
}

// shutdown gracefully stops the servers; the API server first, metrics
// last so the final state can still be scraped.
func shutdown(logger *slog.Logger, servers []*http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var errs []error
	for _, s := range servers {
		if err := s.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown %s: %w", s.Addr, err))
		}
	}
	logger.Info("shutdown complete")
	return errors.Join(errs...)
}

func newJevEvaluator(cfg config.Config, logger *slog.Logger, m *metrics.Metrics) (*jev.Evaluator, error) {
	client, err := jev.NewClient(jev.ClientConfig{
		BaseURL:      cfg.JevURL,
		APIKey:       cfg.JevAPIKey,
		AuthHeader:   cfg.JevAuthHeader,
		AuthScheme:   cfg.JevAuthScheme,
		Timeout:      cfg.JevTimeout,
		EvaluatePath: cfg.JevEvaluatePath,
		Model:        cfg.JevModel,
		HealthPath:   cfg.JevHealthPath,
		MaxConns:     cfg.JevMaxConcurrency,
	})
	if err != nil {
		return nil, fmt.Errorf("configure jev: %w", err)
	}

	var breaker *resilience.Breaker
	if cfg.JevBreakerThreshold > 0 {
		breaker, err = resilience.NewBreaker(resilience.BreakerConfig{
			FailureThreshold:    cfg.JevBreakerThreshold,
			OpenTimeout:         cfg.JevBreakerOpenTimeout,
			HalfOpenMaxRequests: cfg.JevBreakerHalfOpenReqs,
			OnStateChange: func(from, to resilience.State) {
				m.SetBreakerState(from.String(), to.String())
				level := slog.LevelInfo
				if to == resilience.Open {
					level = slog.LevelError
				}
				logger.Log(context.Background(), level, "jev circuit breaker state changed",
					slog.String("from", from.String()), slog.String("to", to.String()))
			},
		})
		if err != nil {
			return nil, fmt.Errorf("configure circuit breaker: %w", err)
		}
	} else {
		logger.Warn("jev circuit breaker is disabled")
	}
	limiter, err := resilience.NewLimiter(cfg.JevMaxConcurrency, cfg.JevQueueTimeout)
	if err != nil {
		return nil, fmt.Errorf("configure concurrency limit: %w", err)
	}
	return jev.NewEvaluator(jev.NewResilientAPI(client, breaker, limiter, m)), nil
}
