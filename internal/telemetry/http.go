package telemetry

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

// Middleware traces every HTTP request with otelhttp: the incoming W3C
// traceparent/baggage headers are extracted so server spans join the caller
// trace, and tenant.id/agency baggage members become span attributes. After
// routing, the span is renamed to the matched ServeMux pattern so span names
// stay low-cardinality. When telemetry is disabled the wrapper is a cheap
// passthrough over a noop tracer and changes nothing on the request path.
func (telemetry *Telemetry) Middleware(operation string, next http.Handler) http.Handler {
	inner := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		next.ServeHTTP(writer, request)
		span := trace.SpanFromContext(request.Context())
		SetBaggageAttributes(request.Context(), span)
	})
	return otelhttp.NewHandler(inner, operation,
		otelhttp.WithTracerProvider(telemetry.TracerProvider()),
		otelhttp.WithMeterProvider(telemetry.MeterProvider()),
		otelhttp.WithPropagators(telemetry.propagator),
		// otelhttp re-applies the formatter after routing when
		// request.Pattern is set, so the final span name is the matched
		// route pattern (low cardinality), falling back to the method.
		otelhttp.WithSpanNameFormatter(func(_ string, request *http.Request) string {
			if request.Pattern != "" {
				return request.Pattern
			}
			return request.Method
		}),
	)
}
