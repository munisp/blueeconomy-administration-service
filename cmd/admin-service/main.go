package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/munisp/blueeconomy-administration-service/internal/admin"
	"github.com/munisp/blueeconomy-administration-service/internal/pbac"
	"github.com/munisp/blueeconomy-administration-service/internal/provenance"
	"github.com/munisp/blueeconomy-administration-service/internal/telemetry"
)

// setupTelemetry builds the OpenTelemetry pipeline from the environment. An
// absent OTEL_EXPORTER_OTLP_ENDPOINT means telemetry is disabled and the
// service boots and serves exactly as before (the one sanctioned fail-open,
// OTEL_DESIGN §1).
func setupTelemetry(ctx context.Context, serviceName string) (*telemetry.Telemetry, error) {
	config, err := telemetry.LoadConfig(serviceName)
	if err != nil {
		return nil, fmt.Errorf("load telemetry config: %w", err)
	}
	pipeline, err := telemetry.Setup(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("setup telemetry: %w", err)
	}
	telemetry.InstallDefault(pipeline)
	if pipeline.Enabled() {
		log.Printf("%s: telemetry enabled (otlp endpoint %s)", serviceName, config.Endpoint)
	} else {
		log.Printf("%s: telemetry disabled (OTEL_EXPORTER_OTLP_ENDPOINT not set)", serviceName)
	}
	return pipeline, nil
}

func main() {
	config, err := admin.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	lifecycleContext, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	pipeline, err := setupTelemetry(lifecycleContext, "admin-service")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := pipeline.Shutdown(context.Background()); err != nil {
			log.Printf("admin-service: telemetry shutdown failed: %v", err)
		}
	}()
	store, err := admin.NewStore(lifecycleContext, config.PostgresDSN)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	// Fail-closed startup: without the producer provenance key no onboarding
	// outbox envelope may be emitted, and without the PBAC policy engine no
	// privileged route may authorize — the process refuses to run at all.
	signer, err := provenance.LoadSignerFromEnv(admin.SigningKeyID)
	if err != nil {
		log.Fatal(err)
	}
	store.WithSigner(signer)
	policyEngine, err := pbac.LoadPolicyDir(config.PBACPolicyDir)
	if err != nil {
		log.Fatal(err)
	}

	keycloakClient, err := admin.NewKeycloakClient(config)
	if err != nil {
		log.Fatal(err)
	}
	service := admin.NewHTTPService(store, keycloakClient, config)
	service.SetPBACEngine(policyEngine)
	store.StartReconciler(lifecycleContext, config.ServiceActorSubject)
	server := &http.Server{
		Addr:              config.ListenAddress,
		Handler:           pipeline.Middleware("admin-service", service.Handler()),
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
