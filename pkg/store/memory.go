package store

import (
	"context"
	"sync"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
)

// Memory is an in-memory implementation of the store. This may be used for
// cases where only one instance of the service is running but is not compatible
// with multi-node deployments.
//
// Note: This implementation does not clean up after itself and will grow
// unbounded over time. This is not for production use.
type Memory struct {
	Map sync.Map
}

// Mark the identifier as in-progress.
func (s *Memory) Mark(ctx context.Context, identifier string) error {
	s.Map.Store(identifier+"-marker", true)
	return nil
}

// Set the value of the identifier.
func (s *Memory) Set(ctx context.Context, identifier string, findings []domain.Finding) error {
	s.Map.Store(identifier, findings)
	return nil
}

// Load the value of the identifier.
func (s *Memory) Load(ctx context.Context, identifier string) ([]domain.Finding, error) {
	f, ok := s.Map.Load(identifier)
	if ok {
		return f.([]domain.Finding), nil
	}
	_, ok = s.Map.Load(identifier + "-marker")
	if ok {
		return nil, domain.InProgressError{Identifier: identifier}
	}
	return nil, domain.NotFoundError{Identifier: identifier}
}

// MemoryConfig contains all settings for the in-memory component.
type MemoryConfig struct{}

// Name of the configuration root.
func (*MemoryConfig) Name() string {
	return "memory"
}

// MemoryComponent implements the component interface for the in-memory option.
type MemoryComponent struct{}

// NewMemoryComponent constructs a default MemoryComponent.
func NewMemoryComponent() *MemoryComponent {
	return &MemoryComponent{}
}

// Settings returns the default configuration.
func (*MemoryComponent) Settings() *MemoryConfig {
	return &MemoryConfig{}
}

// New constructs the component.
func (*MemoryComponent) New(ctx context.Context, conf *MemoryConfig) (domain.Store, error) {
	return &Memory{}, nil
}
