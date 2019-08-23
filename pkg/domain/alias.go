package domain

import (
	"context"

	"github.com/asecurityteam/runhttp"
)

// Logger is the project logger interface.
type Logger = runhttp.Logger

// LogFn is the recommended way to extract a logger from the context.
type LogFn = runhttp.LogFn

// Stat is the project metrics client interface.
type Stat = runhttp.Stat

// StatFn is the recommended way to extract a metrics client from the context.
type StatFn = runhttp.StatFn

// Producer is used to ship results to a destination.
type Producer interface {
	Produce(ctx context.Context, event interface{}) (interface{}, error)
}
