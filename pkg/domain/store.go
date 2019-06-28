package domain

import (
	"context"
	"fmt"
)

// InProgressError is returned from Load when the value is not present but
// the work is in progress.
type InProgressError struct {
	Identifier string
}

func (e InProgressError) Error() string {
	return fmt.Sprintf("work for %s is still in progress", e.Identifier)
}

// NotFoundError is returned from Load when the value is neither set nor is
// is there a progress marker.
type NotFoundError struct {
	Identifier string
}

func (e NotFoundError) Error() string {
	return fmt.Sprintf("no work in progress or results for %s", e.Identifier)
}

// Store is used to track the results of scans.
type Store interface {
	// Mark the identifier as in-progress.
	Mark(ctx context.Context, identifier string) error
	// Set the value of the identifier.
	Set(ctx context.Context, identifier string, finding Finding) error
	// Load the value of the identifier.
	Load(ctx context.Context, identifier string) (Finding, error)
}
