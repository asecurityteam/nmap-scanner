package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
)

const (
	// TypeMemory indicates the in-memory selection.
	TypeMemory = "MEMORY"
	// TypeDynamo indicates the AWS DynamoDB selection.
	TypeDynamo = "DYNAMODB"
)

// Config is the top level aggregate of all store implemenations.
type Config struct {
	Type   string `description:"The type of data store to use for results tracking."`
	Memory *MemoryConfig
	Dynamo *DynamoConfig
}

// Name of the configuration root.
func (*Config) Name() string {
	return "store"
}

// Component is the top level aggregate of all store components.
type Component struct {
	Memory *MemoryComponent
	Dynamo *DynamoComponent
}

// NewComponent constructs a default component.
func NewComponent() *Component {
	return &Component{
		Memory: NewMemoryComponent(),
		Dynamo: NewDynamoComponent(),
	}
}

// Settings returns the default configuration.
func (c *Component) Settings() *Config {
	return &Config{
		Type:   TypeMemory,
		Memory: c.Memory.Settings(),
		Dynamo: c.Dynamo.Settings(),
	}
}

// New generates a store from the configuration.
func (c *Component) New(ctx context.Context, conf *Config) (domain.Store, error) {
	switch {
	case strings.EqualFold(conf.Type, TypeMemory):
		return c.Memory.New(ctx, conf.Memory)
	case strings.EqualFold(conf.Type, TypeDynamo):
		return c.Dynamo.New(ctx, conf.Dynamo)
	default:
		return nil, fmt.Errorf("unknown store type %s", conf.Type)
	}
}
