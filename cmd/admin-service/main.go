package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/munisp/blueeconomy-administration-service/internal/admin"
	"github.com/munisp/blueeconomy-administration-service/internal/telemetry"
)

func main() {
	config, err := admin.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	lifecycleContext, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	telemetryConfig, err := telemetry.LoadConfig("blueeconomy-administration-service")
	if err != nil {
		log.Fatal(err)
	}
	pipeline, err := telemetry.Setup(lifecycleContext, telemetryConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		shutdown, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := pipeline.Shutdown(shutdown); err != nil {
			log.Printf("telemetry shutdown: %v", err)
		}
	}()
	if pipeline.Enabled() {
		log.Printf("telemetry: OTLP gRPC traces exporting to %s; Prometheus metrics on GET /metrics", telemetryConfig.Endpoint)
	} else {
		log.Printf("telemetry: tracing disabled (OTEL_EXPORTER_OTLP_ENDPOINT not set); running with an explicit no-op tracer, Prometheus metrics on GET /metrics")
	}
	store, err := admin.NewStore(lifecycleContext, config.PostgresDSN)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	keycloakClient, err := admin.NewKeycloakClient(config)
	if err != nil {
		log.Fatal(err)
	}
	service := admin.NewHTTPService(store, keycloakClient, config)
	service.Instrument(pipeline)
	store.StartReconciler(lifecycleContext, config.ServiceActorSubject)
	server := &http.Server{
		Addr:              config.ListenAddress,
		Handler:           service.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		log.Printf("central administration service listening on %s", config.ListenAddress)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	<-lifecycleContext.Done()
	shutdown, shutdownCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdown); err != nil {
		log.Fatal(err)
	}
}
