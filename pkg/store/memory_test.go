package store

import (
	"context"
	"testing"
	"time"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
	"github.com/stretchr/testify/require"
)

func TestMemory(t *testing.T) {
	cmp := NewMemoryComponent()
	ctx := context.Background()
	id := "test"

	s, err := cmp.New(ctx, cmp.Settings())
	require.Nil(t, err)
	require.NotNil(t, s)

	_, err = s.Load(ctx, id)
	require.NotNil(t, err)
	require.IsType(t, domain.NotFoundError{}, err)

	err = s.Mark(ctx, id)
	require.Nil(t, err)
	_, err = s.Load(ctx, id)
	require.NotNil(t, err)
	require.IsType(t, domain.InProgressError{}, err)

	expected := []domain.Finding{{Timestamp: time.Now()}}
	err = s.Set(ctx, id, expected)
	require.Nil(t, err)
	r, err := s.Load(ctx, id)
	require.Nil(t, err)
	require.Equal(t, expected, r)
}
