package telemetry

import (
	"context"
	"fmt"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPGXPool opens a pgx pool with the otelpgx tracer installed: every query,
// batch, copy and acquire emits a client span that joins the caller trace.
// With telemetry disabled the tracer runs over a noop provider and records
// nothing; pool semantics are unchanged.
func (telemetry *Telemetry) NewPGXPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse postgres DSN: %w", err)
	}
	config.ConnConfig.Tracer = otelpgx.NewTracer(otelpgx.WithTracerProvider(telemetry.TracerProvider()))
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	return pool, nil
}
