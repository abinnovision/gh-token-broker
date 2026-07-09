// Command gh-token-broker authenticates GitHub Actions OIDC callers,
// evaluates operator-authored CEL policy, and mints least-privilege GitHub App
// installation tokens — either by dispatching a workflow itself or by
// returning a scoped token to the caller.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/abinnovision/gh-token-broker/internal/actions"
	"github.com/abinnovision/gh-token-broker/internal/audit"
	"github.com/abinnovision/gh-token-broker/internal/auth"
	"github.com/abinnovision/gh-token-broker/internal/config"
	"github.com/abinnovision/gh-token-broker/internal/githubapp"
	"github.com/abinnovision/gh-token-broker/internal/policy"
	"github.com/abinnovision/gh-token-broker/internal/server"
)

// version is injected by GoReleaser via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger, *configPath); err != nil {
		logger.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	for _, warning := range cfg.Lint() {
		logger.Warn("config lint", "warning", warning)
	}

	ctx := context.Background()
	authn, err := auth.New(ctx, cfg.OIDC.Issuer, cfg.OIDC.Audience,
		time.Duration(cfg.OIDC.ClockSkewSeconds)*time.Second)
	if err != nil {
		return err
	}

	engine, err := policy.New(cfg, logger)
	if err != nil {
		return err
	}

	ghClient, err := githubapp.New(cfg.GitHubApp, logger)
	if err != nil {
		return err
	}

	auditLog := audit.New(logger)
	srv := server.New(authn, engine, ghClient, actions.GitHubDispatcher{},
		auditLog, logger, cfg.TokenIssuance.Enabled)

	httpServer := &http.Server{
		Addr:              cfg.Server.Bind,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	shutdownCtx, stop := signalContext()
	defer stop()
	go func() {
		<-shutdownCtx.Done()
		logger.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()

	logger.Info("listening",
		"bind", cfg.Server.Bind,
		"version", version,
		"rules", len(cfg.Policy.Rules),
		"token_issuance_enabled", cfg.TokenIssuance.Enabled)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
