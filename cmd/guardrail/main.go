// Command guardrail runs the Jev Guardrail decision API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/alpkeskin/jev-guardrail/internal/policy"
)

func main() {
	if err := run(); err != nil {
		slog.Error("guardrail exited", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(nil)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger, err := logging.New(os.Stdout, cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	// Startup fails if default.yaml (or any policy) is missing or invalid.
	store, err := policy.Load(cfg.PolicyDir)
	if err != nil {
		return fmt.Errorf("load policies: %w", err)
	}
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

	jevClient, err := jev.NewClient(jev.ClientConfig{
		BaseURL:      cfg.JevURL,
		APIKey:       cfg.JevAPIKey,
		Timeout:      cfg.JevTimeout,
		EvaluatePath: cfg.JevEvaluatePath,
		HealthPath:   cfg.JevHealthPath,
	})
	if err != nil {
		return fmt.Errorf("configure jev: %w", err)
	}
	service := guardrail.NewService(jev.NewEvaluator(jevClient), guardrail.ThresholdEngine{})

	handler := api.NewHandler(service, cfg.MaxBodyBytes, []api.ReadinessCheck{
		{Name: "policies", Check: func(context.Context) error { return nil }}, // loaded and validated at startup
		{Name: "jev", Check: service.Ready},
	})
	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: api.NewRouter(api.RouterConfig{
			Logger:        logger,
			Handler:       handler,
			Authenticator: authn,
			Resolver:      store,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      cfg.JevTimeout + 15*time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("guardrail listening", slog.String("addr", cfg.Addr))
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
