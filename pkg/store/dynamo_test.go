package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDynamoComponent(t *testing.T) {
	cmp := NewDynamoComponent()
	conf := cmp.Settings()

	require.Equal(t, "dynamodb", conf.Name())
	require.Equal(t, "aws", conf.AWS.Name())
}
