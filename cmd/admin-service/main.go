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
	"github.com/munisp/blueeconomy-administration-service/internal/pbac"
	"github.com/munisp/blueeconomy-administration-service/internal/provenance"
)

func main() {
	config, err := admin.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	lifecycleContext, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
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
