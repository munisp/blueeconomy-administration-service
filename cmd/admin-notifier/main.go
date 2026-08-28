package main

import (
	"context"
	"expvar"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/munisp/blueeconomy-administration-service/internal/admin"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	config, err := admin.LoadNotifierConfig()
	if err != nil {
		logger.Error("admin-notifier configuration invalid", "error", err)
		os.Exit(1)
	}
	lifecycleContext, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	store, err := admin.NewStore(lifecycleContext, config.PostgresDSN)
	if err != nil {
		logger.Error("admin-notifier cannot reach PostgreSQL", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	channel, err := config.BuildChannel()
	if err != nil {
		logger.Error("admin-notifier channel cannot be built", "error", err)
		os.Exit(1)
	}
	var metricsServer *http.Server
	if config.MetricsAddress != "" {
		mux := http.NewServeMux()
		mux.Handle("/debug/vars", expvar.Handler())
		metricsServer = &http.Server{
			Addr:              config.MetricsAddress,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			logger.Info("admin-notifier metrics listening", "address", config.MetricsAddress)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("admin-notifier metrics listener failed", "error", err)
			}
		}()
	}
	logger.Info("admin-notifier starting",
		"channel", config.Channel,
		"batch_size", config.BatchSize,
		"poll_interval", config.PollInterval.String(),
		"max_attempts", config.MaxAttempts,
	)
	notifier := admin.NewNotifier(store, channel, config, logger)
	if err := notifier.Run(lifecycleContext); err != nil {
		logger.Error("admin-notifier stopped with error", "error", err)
		os.Exit(1)
	}
	if metricsServer != nil {
		shutdown, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = metricsServer.Shutdown(shutdown)
	}
	logger.Info("admin-notifier stopped")
}
