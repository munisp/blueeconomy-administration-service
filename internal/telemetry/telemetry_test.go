package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// newRecordingPipeline builds an enabled Telemetry whose spans land in an
// in-process recorder, so tests assert on real SDK behavior without any
// collector.
func newRecordingPipeline(t *testing.T) (*Telemetry, *tracetest.SpanRecorder) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	pipeline, err := NewPipelineForTest(tracerProvider, "telemetry-test")
	require.NoError(t, err)
	return pipeline, recorder
}

// TestHTTPPropagationRoundTripAndBaggageAttributes proves the otelhttp server
// middleware joins the caller trace from the traceparent header and stamps
// tenant.id/agency baggage onto the server span (tenant attribution,
// OTEL_DESIGN §2).
func TestHTTPPropagationRoundTripAndBaggageAttributes(t *testing.T) {
	pipeline, recorder := newRecordingPipeline(t)
	handler := pipeline.Middleware("admin-service", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/onboarding/req-1/decision", nil)
	request.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	request.Header.Set("baggage", "tenant.id=tenant-rivers,agency=FMMBE")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	spans := recorder.Ended()
	require.Len(t, spans, 1, "exactly one server span must be recorded")
	serverSpan := spans[0]
	require.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", serverSpan.SpanContext().TraceID().String(), "server span must join the caller trace")
	require.Equal(t, trace.SpanKindServer, serverSpan.SpanKind())
	var tenant, agency string
	for _, kv := range serverSpan.Attributes() {
		switch string(kv.Key) {
		case "tenant.id":
			tenant = kv.Value.AsString()
		case "agency":
			agency = kv.Value.AsString()
		}
	}
	require.Equal(t, "tenant-rivers", tenant, "tenant.id baggage must become a span attribute")
	require.Equal(t, "FMMBE", agency, "agency baggage must become a span attribute")
}

// TestHTTPPropagationRoundTripResponseHeader is the second half of the HTTP
// round-trip: an instrumented client injecting into an outgoing request and
// the server extracting it must reproduce the same trace context.
func TestHTTPPropagationRoundTripResponseHeader(t *testing.T) {
	pipeline, recorder := newRecordingPipeline(t)
	ctx, clientSpan := pipeline.StartSpan(context.Background(), "client", trace.SpanKindClient)
	request := httptest.NewRequest(http.MethodGet, "/v1/onboarding", nil)
	pipeline.Propagator().Inject(ctx, propagation.HeaderCarrier(request.Header))
	clientSpan.End()

	handler := pipeline.Middleware("admin-service", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request)

	serverSpan := endedSpan(t, recorder, http.MethodGet)
	client := endedSpan(t, recorder, "client")
	require.Equal(t, client.SpanContext().TraceID(), serverSpan.SpanContext().TraceID(), "server span must join the client trace through the injected header")
	require.Equal(t, client.SpanContext().SpanID(), serverSpan.Parent().SpanID())
}

func endedSpan(t *testing.T, recorder *tracetest.SpanRecorder, name string) sdktrace.ReadOnlySpan {
	t.Helper()
	for _, span := range recorder.Ended() {
		if span.Name() == name {
			return span
		}
	}
	t.Fatalf("no ended span named %q (have %d spans)", name, len(recorder.Ended()))
	return nil
}

// TestDisabledTelemetryBootAndRequest proves the sanctioned fail-open: with
// no OTLP endpoint the pipeline sets up cleanly, middleware serves requests
// unchanged, spans are non-recording, and shutdown is a noop.
func TestDisabledTelemetryBootAndRequest(t *testing.T) {
	pipeline, err := Setup(context.Background(), Config{ServiceName: "disabled-test"})
	require.NoError(t, err)
	require.False(t, pipeline.Enabled())

	called := false
	handler := pipeline.Middleware("disabled-test", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		called = true
		writer.WriteHeader(http.StatusTeapot)
	}))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/anything", nil)
	request.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	handler.ServeHTTP(recorder, request)
	require.True(t, called, "request must be served with telemetry disabled")
	require.Equal(t, http.StatusTeapot, recorder.Code)

	_, span := pipeline.StartSpan(context.Background(), "noop", trace.SpanKindInternal)
	require.False(t, span.IsRecording())
	span.End()
	pipeline.RecordMoneyOp(context.Background(), "decide")
	require.NoError(t, pipeline.Shutdown(context.Background()))
}

// TestDropCountingExporter proves collector-down export failures are counted
// on telemetry_dropped_total, never surfaced to callers as request failures.
func TestDropCountingExporter(t *testing.T) {
	dropped := &atomic.Int64{}
	exporter := &dropCountingExporter{inner: failingExporter{}, dropped: dropped}
	err := exporter.ExportSpans(context.Background(), make([]sdktrace.ReadOnlySpan, 5))
	require.Error(t, err, "the batcher still sees the failure (it logs and discards)")
	require.Equal(t, int64(5), dropped.Load())
}

type failingExporter struct{}

func (failingExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	return errors.New("collector unreachable")
}

func (failingExporter) Shutdown(context.Context) error { return nil }

// TestLoadConfigContract pins the endpoint contract: unset = disabled,
// malformed = fail-closed startup error.
func TestLoadConfigContract(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_SDK_DISABLED", "")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "")
	config, err := LoadConfig("contract-test")
	require.NoError(t, err)
	require.False(t, config.Enabled, "unset endpoint must mean telemetry disabled")

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "not-a-host-port")
	_, err = LoadConfig("contract-test")
	require.Error(t, err, "malformed endpoint fails closed")

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector:4317")
	config, err = LoadConfig("contract-test")
	require.NoError(t, err)
	require.True(t, config.Enabled)
	require.Equal(t, "otel-collector:4317", config.Endpoint)
}
