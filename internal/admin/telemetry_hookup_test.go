package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/munisp/blueeconomy-administration-service/internal/telemetry"
)

// TestInstrumentedHandlerServesMetricsAndReadyz proves the operational
// surface: the Prometheus endpoint is mounted when the service is
// instrumented, and /readyz fails closed when no evidence store is wired.
func TestInstrumentedHandlerServesMetricsAndReadyz(t *testing.T) {
	pipeline, err := telemetry.Setup(context.Background(), telemetry.Config{ServiceName: "admin-test"})
	if err != nil {
		t.Fatalf("disabled telemetry setup must succeed: %v", err)
	}
	t.Cleanup(func() { _ = pipeline.Shutdown(context.Background()) })
	service := newStubService(RolePlatformAdmin)
	service.Instrument(pipeline)
	handler := service.Handler()

	metricsResponse := httptest.NewRecorder()
	handler.ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsResponse.Code != http.StatusOK {
		t.Fatalf("GET /metrics must serve 200, got %d", metricsResponse.Code)
	}

	readyResponse := httptest.NewRecorder()
	handler.ServeHTTP(readyResponse, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if readyResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz without a store must fail closed with 503, got %d", readyResponse.Code)
	}
}

// TestUninstrumentedHandlerHasNoMetricsRoute keeps the zero-telemetry
// construction (unit-test path) free of any metrics surface.
func TestUninstrumentedHandlerHasNoMetricsRoute(t *testing.T) {
	handler := newStubService(RolePlatformAdmin).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("GET /metrics without instrumentation must hit default-deny 403, got %d", response.Code)
	}
}
