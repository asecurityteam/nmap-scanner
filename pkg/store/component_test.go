package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoreComponent(t *testing.T) {
	cmp := NewComponent()
	conf := cmp.Settings()
	require.Equal(t, "store", conf.Name())

	conf.Type = TypeMemory
	s, err := cmp.New(context.Background(), conf)
	require.Nil(t, err)
	require.NotNil(t, s)

	conf.Type = TypeDynamo
	s, err = cmp.New(context.Background(), conf)
	require.Nil(t, err)
	require.NotNil(t, s)

	conf.Type = "UNKNOWN"
	_, err = cmp.New(context.Background(), conf)
	require.NotNil(t, err)
}
