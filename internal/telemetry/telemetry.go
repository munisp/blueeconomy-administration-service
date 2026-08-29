// Package telemetry wires OpenTelemetry tracing and metrics for the
// administration service under the Phase-7 OTLP contract
// (blueeconomy-review/phase7/OTEL_DESIGN.md):
//
//   - OTEL_EXPORTER_OTLP_ENDPOINT unset means telemetry is DISABLED; a
//     disabled service boots and serves requests exactly as before (the one
//     sanctioned fail-open in the platform).
//   - When the endpoint is set, export is async/batched and non-blocking; an
//     unreachable collector means spans are dropped and counted on
//     telemetry_dropped_total — never a request failure.
//   - Propagation is W3C tracecontext+baggage; tenant.id and agency baggage
//     members become attributes on every server span. Metrics stay
//     low-cardinality: the tenant label appears only on money counters.
//   - Shutdown flush is bounded at 5 seconds.
//
// Configuration parsing follows the platform fail-closed posture: a malformed
// endpoint or a contradictory OTEL_SDK_DISABLED is a startup error.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	otlpmetricgrpc "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	otlptracegrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// ShutdownTimeout bounds the graceful telemetry flush on process shutdown.
const ShutdownTimeout = 5 * time.Second

// DroppedMetricName counts telemetry batches dropped because the collector
// was unreachable; dropping must never fail a request.
const DroppedMetricName = "telemetry_dropped_total"

// MoneyCounterName is the low-cardinality money-operation counter; it is the
// only metric permitted to carry the tenant.id label (OTEL_DESIGN §2).
const MoneyCounterName = "money_operations_total"

// Config is the validated telemetry configuration. Enabled is false when no
// OTLP endpoint is configured; every other field is then ignored.
type Config struct {
	Enabled     bool
	Endpoint    string
	Insecure    bool
	ServiceName string
}

// LoadConfig reads OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_INSECURE,
// OTEL_SERVICE_NAME and OTEL_SDK_DISABLED. An absent endpoint means telemetry
// is disabled; a present but malformed endpoint, an unknown boolean value, or
// a contradictory OTEL_SDK_DISABLED=true fails closed.
func LoadConfig(serviceName string) (Config, error) {
	if strings.TrimSpace(serviceName) == "" {
		return Config{}, errors.New("telemetry service name is required")
	}
	config := Config{ServiceName: serviceName}
	if override := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); override != "" {
		if len(override) > 128 {
			return Config{}, errors.New("OTEL_SERVICE_NAME must be at most 128 characters")
		}
		config.ServiceName = override
	}
	disabled, err := parseBoolean("OTEL_SDK_DISABLED")
	if err != nil {
		return Config{}, err
	}
	insecure, err := parseBoolean("OTEL_EXPORTER_OTLP_INSECURE")
	if err != nil {
		return Config{}, err
	}
	config.Insecure = insecure
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if disabled {
		if endpoint != "" {
			return Config{}, errors.New("OTEL_SDK_DISABLED=true conflicts with OTEL_EXPORTER_OTLP_ENDPOINT; remove one (fail-closed)")
		}
		return config, nil
	}
	if endpoint == "" {
		return config, nil
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return Config{}, fmt.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT must be a host:port pair without scheme, credentials or path: %q", endpoint)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Config{}, fmt.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT has an invalid port: %q", endpoint)
	}
	config.Enabled = true
	config.Endpoint = endpoint
	return config, nil
}

// parseBoolean accepts only empty, "true" or "false"; anything else fails
// closed rather than being silently interpreted.
func parseBoolean(name string) (bool, error) {
	switch value := strings.TrimSpace(os.Getenv(name)); value {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be true or false when set", name)
	}
}

// Telemetry carries the tracer/meter pipelines and the propagator. Use Setup
// (or LoadConfig+Setup) to build one; the zero value is not usable.
type Telemetry struct {
	config         Config
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	tracer         trace.Tracer
	meter          metric.Meter
	propagator     propagation.TextMapPropagator
	dropped        *atomic.Int64
	moneyOps       metric.Int64Counter
}

// Setup builds the telemetry pipelines. When the config is disabled the
// result is fully no-op (explicit noop tracer/meter, no exporters) and boot
// and request paths are byte-identical to an uninstrumented service.
func Setup(ctx context.Context, config Config) (*Telemetry, error) {
	if strings.TrimSpace(config.ServiceName) == "" {
		return nil, errors.New("telemetry service name is required")
	}
	serviceResource := resource.NewSchemaless(attribute.String("service.name", config.ServiceName))
	telemetry := &Telemetry{
		config:     config,
		dropped:    &atomic.Int64{},
		propagator: propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}),
	}
	if !config.Enabled {
		telemetry.tracer = tracenoop.NewTracerProvider().Tracer(config.ServiceName)
		telemetry.meter = metricnoop.NewMeterProvider().Meter(config.ServiceName)
		if err := telemetry.initMoneyCounter(); err != nil {
			return nil, err
		}
		return telemetry, nil
	}
	exporterOptions := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(config.Endpoint)}
	metricExporterOptions := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(config.Endpoint)}
	if config.Insecure {
		exporterOptions = append(exporterOptions, otlptracegrpc.WithInsecure())
		metricExporterOptions = append(metricExporterOptions, otlpmetricgrpc.WithInsecure())
	}
	traceExporter, err := otlptracegrpc.New(ctx, exporterOptions...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP gRPC trace exporter: %w", err)
	}
	metricExporter, err := otlpmetricgrpc.New(ctx, metricExporterOptions...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP gRPC metric exporter: %w", err)
	}
	telemetry.tracerProvider = sdktrace.NewTracerProvider(
		// The batcher is async and non-blocking; export failures drop the
		// batch and are counted, never surfaced on the request path.
		sdktrace.WithBatcher(&dropCountingExporter{inner: traceExporter, dropped: telemetry.dropped}),
		sdktrace.WithResource(serviceResource),
	)
	telemetry.meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
		sdkmetric.WithResource(serviceResource),
	)
	telemetry.tracer = telemetry.tracerProvider.Tracer(config.ServiceName)
	telemetry.meter = telemetry.meterProvider.Meter(config.ServiceName)
	if err := telemetry.initMoneyCounter(); err != nil {
		return nil, err
	}
	meter := telemetry.meter
	dropped := telemetry.dropped
	if _, err := meter.Int64ObservableCounter(DroppedMetricName,
		metric.WithDescription("Telemetry batches dropped because the collector was unreachable"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(dropped.Load())
			return nil
		}),
	); err != nil {
		return nil, fmt.Errorf("create dropped-telemetry counter: %w", err)
	}
	return telemetry, nil
}

func (telemetry *Telemetry) initMoneyCounter() error {
	counter, err := telemetry.meter.Int64Counter(MoneyCounterName,
		metric.WithDescription("Money-path ledger operations partitioned by operation, ledger and tenant"))
	if err != nil {
		return fmt.Errorf("create money-operation counter: %w", err)
	}
	telemetry.moneyOps = counter
	return nil
}

// dropCountingExporter wraps the OTLP exporter: a failed export (collector
// down, backoff exhausted) increments telemetry_dropped_total. The error is
// still returned to the batcher (which logs and discards the batch); it never
// reaches the request path.
type dropCountingExporter struct {
	inner   sdktrace.SpanExporter
	dropped *atomic.Int64
}

func (exporter *dropCountingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := exporter.inner.ExportSpans(ctx, spans)
	if err != nil {
		exporter.dropped.Add(int64(len(spans)))
	}
	return err
}

func (exporter *dropCountingExporter) Shutdown(ctx context.Context) error {
	return exporter.inner.Shutdown(ctx)
}

// Enabled reports whether OTLP export is active.
func (telemetry *Telemetry) Enabled() bool { return telemetry.config.Enabled }

// Tracer returns the service tracer (noop when disabled).
func (telemetry *Telemetry) Tracer() trace.Tracer { return telemetry.tracer }

// TracerProvider returns the SDK tracer provider when enabled, otherwise an
// explicit noop provider — instrumentation wrappers always get a usable
// provider.
func (telemetry *Telemetry) TracerProvider() trace.TracerProvider {
	if telemetry.tracerProvider != nil {
		return telemetry.tracerProvider
	}
	return tracenoop.NewTracerProvider()
}

// MeterProvider returns the SDK meter provider when enabled, otherwise an
// explicit noop provider.
func (telemetry *Telemetry) MeterProvider() metric.MeterProvider {
	if telemetry.meterProvider != nil {
		return telemetry.meterProvider
	}
	return metricnoop.NewMeterProvider()
}

// Propagator returns the W3C tracecontext+baggage propagator.
func (telemetry *Telemetry) Propagator() propagation.TextMapPropagator {
	return telemetry.propagator
}

// Dropped returns the number of spans dropped on failed exports so far.
func (telemetry *Telemetry) Dropped() int64 { return telemetry.dropped.Load() }

// StartSpan starts one span on the service tracer; with telemetry disabled
// this is a cheap non-recording noop span, so call sites never branch on
// Enabled.
func (telemetry *Telemetry) StartSpan(ctx context.Context, name string, kind trace.SpanKind, attributes ...attribute.KeyValue) (context.Context, trace.Span) {
	options := []trace.SpanStartOption{trace.WithSpanKind(kind)}
	if len(attributes) > 0 {
		options = append(options, trace.WithAttributes(attributes...))
	}
	return telemetry.tracer.Start(ctx, name, options...)
}

// RecordMoneyOp increments the money-operation counter. The tenant.id label
// (from baggage) is attached only here — every other metric stays
// tenant-free to keep cardinality low (OTEL_DESIGN §2).
func (telemetry *Telemetry) RecordMoneyOp(ctx context.Context, operation string, attributes ...attribute.KeyValue) {
	if telemetry.moneyOps == nil {
		return
	}
	all := append([]attribute.KeyValue{attribute.String("operation", operation)}, attributes...)
	if tenant := baggage.FromContext(ctx).Member("tenant.id"); tenant.Value() != "" {
		all = append(all, attribute.String("tenant.id", tenant.Value()))
	}
	telemetry.moneyOps.Add(ctx, 1, metric.WithAttributes(all...))
}

// Shutdown flushes and stops both providers, bounded at ShutdownTimeout so a
// dead collector cannot stall process exit.
func (telemetry *Telemetry) Shutdown(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, ShutdownTimeout)
	defer cancel()
	var shutdownErr error
	if telemetry.tracerProvider != nil {
		shutdownErr = telemetry.tracerProvider.Shutdown(bounded)
	}
	if telemetry.meterProvider != nil {
		if err := telemetry.meterProvider.Shutdown(bounded); shutdownErr == nil {
			shutdownErr = err
		}
	}
	return shutdownErr
}

// NewPipelineForTest builds an enabled Telemetry over an arbitrary SDK tracer
// provider (e.g. one backed by tracetest.SpanRecorder) so unit tests in
// instrumented packages can assert on spans without a collector.
func NewPipelineForTest(tracerProvider *sdktrace.TracerProvider, serviceName string) (*Telemetry, error) {
	if tracerProvider == nil {
		return nil, errors.New("tracer provider is required")
	}
	pipeline := &Telemetry{
		config:         Config{Enabled: true, ServiceName: serviceName},
		tracerProvider: tracerProvider,
		tracer:         tracerProvider.Tracer(serviceName),
		propagator:     propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}),
		dropped:        &atomic.Int64{},
	}
	pipeline.meter = metricnoop.NewMeterProvider().Meter(serviceName)
	if err := pipeline.initMoneyCounter(); err != nil {
		return nil, err
	}
	return pipeline, nil
}

// SetBaggageAttributes copies the tenant.id and agency baggage members onto
// the span as attributes (tenant attribution per OTEL_DESIGN §2). It is a
// noop when the span is not recording or no baggage is present.
func SetBaggageAttributes(ctx context.Context, span trace.Span) {
	if span == nil || !span.IsRecording() {
		return
	}
	bag := baggage.FromContext(ctx)
	if tenant := bag.Member("tenant.id"); tenant.Value() != "" {
		span.SetAttributes(attribute.String("tenant.id", tenant.Value()))
	}
	if agency := bag.Member("agency"); agency.Value() != "" {
		span.SetAttributes(attribute.String("agency", agency.Value()))
	}
}

// defaultPipeline is the process-wide telemetry used by library-level
// instrumentation (ledger, tariff, kafka carriers) whose signatures cannot
// carry a *Telemetry. It is installed by InstallDefault at service boot and
// defaults to a fully disabled pipeline, so unit tests and binaries that
// never call Setup still behave as telemetry-disabled.
var defaultPipeline atomic.Pointer[Telemetry]

// InstallDefault registers the process-wide pipeline; cmd binaries call it
// immediately after Setup.
func InstallDefault(telemetry *Telemetry) {
	if telemetry == nil {
		return
	}
	defaultPipeline.Store(telemetry)
	if telemetry.Enabled() {
		otel.SetTracerProvider(telemetry.tracerProvider)
		otel.SetMeterProvider(telemetry.meterProvider)
	}
	otel.SetTextMapPropagator(telemetry.propagator)
}

// Default returns the process-wide pipeline, or a disabled one when none was
// installed.
func Default() *Telemetry {
	if telemetry := defaultPipeline.Load(); telemetry != nil {
		return telemetry
	}
	telemetry, err := Setup(context.Background(), Config{ServiceName: "blueeconomy-administration-service"})
	if err != nil { // unreachable: the disabled path has no error branch beyond an empty name
		panic(err)
	}
	defaultPipeline.CompareAndSwap(nil, telemetry)
	return defaultPipeline.Load()
}
