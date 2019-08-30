package scanner

import (
	"context"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
)

type nopLogger struct{}

func (*nopLogger) Debug(event interface{})                 {}
func (*nopLogger) Info(event interface{})                  {}
func (*nopLogger) Warn(event interface{})                  {}
func (*nopLogger) Error(event interface{})                 {}
func (*nopLogger) SetField(name string, value interface{}) {}
func (logger *nopLogger) Copy() domain.Logger {
	return logger
}

func testLogFn(context.Context) domain.Logger { return &nopLogger{} }
