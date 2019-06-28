package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
)

const (
	dataKey             = "data"
	marker              = "OK"
	defaultPartitionKey = "identity"
	deafultTTLKey       = "ttl"
	defaultTableName    = "ScanResults"
)

type dynamoResult struct {
	PartitionKey string `json:"partitionKey"`
	Data         string `json:"data"`
}

type vulnerability struct {
	ID             string `json:"id"`
	Description    string `json:"description"`
	Product        string `json:"product"`
	ProductVersion string `json:"productVersion"`
	Link           string `json:"link"`
	Source         string `json:"source"`
	Port           int    `json:"port"`
	Protocol       string `json:"protocol"`
	Service        string `json:"service"`
}

type finding struct {
	Timestamp       time.Time       `json:"timestamp"`
	IP              string          `json:"ip"`
	Hostnames       []string        `json:"hostnames"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

func fromDomain(f domain.Finding) finding {
	sv := make([]vulnerability, 0, len(f.Vulnerabilities))
	for _, vuln := range f.Vulnerabilities {
		sv = append(sv, vulnerability(vuln))
	}
	return finding{
		Timestamp:       f.Timestamp,
		IP:              f.IP,
		Hostnames:       f.Hostnames,
		Vulnerabilities: sv,
	}
}

func toDomain(f finding) domain.Finding {
	sv := make([]domain.Vulnerability, 0, len(f.Vulnerabilities))
	for _, vuln := range f.Vulnerabilities {
		sv = append(sv, domain.Vulnerability(vuln))
	}
	return domain.Finding{
		Timestamp:       f.Timestamp,
		IP:              f.IP,
		Hostnames:       f.Hostnames,
		Vulnerabilities: sv,
	}
}

// DynamoDB implements store using AWS DynamoDB.
type DynamoDB struct {
	Client           dynamodbiface.DynamoDBAPI
	TableName        string
	PartitionKeyName string
	TTLKeyName       string
}

// Mark the identifier as in-progress.
func (s *DynamoDB) Mark(ctx context.Context, identifier string) error {
	_, err := s.Client.PutItemWithContext(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.TableName),
		Item: map[string]*dynamodb.AttributeValue{
			s.PartitionKeyName: {
				S: aws.String(identifier + "-marker"),
			},
			dataKey: {
				S: aws.String(marker),
			},
			s.TTLKeyName: {
				N: aws.String(fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix())),
			},
		},
	})
	return err
}

// Set the value of the identifier.
func (s *DynamoDB) Set(ctx context.Context, identifier string, finding domain.Finding) error {
	b, _ := json.Marshal(fromDomain(finding))
	_, err := s.Client.PutItemWithContext(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.TableName),
		Item: map[string]*dynamodb.AttributeValue{
			s.PartitionKeyName: {
				S: aws.String(identifier),
			},
			dataKey: {
				S: aws.String(string(b)),
			},
			s.TTLKeyName: {
				N: aws.String(fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix())),
			},
		},
	})
	return err
}

// Load the value of the identifier.
func (s *DynamoDB) Load(ctx context.Context, identifier string) (domain.Finding, error) {
	item, err := s.Client.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.TableName),
		Key: map[string]*dynamodb.AttributeValue{
			s.PartitionKeyName: {
				S: aws.String(identifier),
			},
		},
	})
	if err != nil {
		return domain.Finding{}, err
	}

	var result dynamoResult
	err = dynamodbattribute.UnmarshalMap(item.Item, &result)
	if err == nil {
		var f finding
		err = json.Unmarshal([]byte(result.Data), &f)
		if err != nil {
			return domain.Finding{}, err
		}
		return toDomain(f), nil
	}

	item, err = s.Client.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.TableName),
		Key: map[string]*dynamodb.AttributeValue{
			s.PartitionKeyName: {
				S: aws.String(identifier + "-marker"),
			},
		},
	})
	if err != nil {
		return domain.Finding{}, err
	}
	err = dynamodbattribute.UnmarshalMap(item.Item, &result)
	if err == nil && result.Data == marker {
		return domain.Finding{}, domain.InProgressError{Identifier: identifier}
	}
	return domain.Finding{}, domain.NotFoundError{Identifier: identifier}
}

// DynamoConfig contains all settings for the in-memory component.
type DynamoConfig struct {
	TableName    string `description:"The name of the DynamoDB table to use."`
	PartitionKey string `description:"Name of the table partition key."`
	TTLKey       string `description:"Name of the TTL key."`
	Region       string `description:"AWS region in which the table is provisioned."`
	Endpoint     string `descriptions:"DynamoDB endpoint to use for requests."`
}

// Name of the configuration root.
func (*DynamoConfig) Name() string {
	return "dynamodb"
}

// DynamoComponent implements the component interface for the in-memory option.
type DynamoComponent struct{}

// NewDynamoComponent constructs a default DynamoComponent.
func NewDynamoComponent() *DynamoComponent {
	return &DynamoComponent{}
}

// Settings returns the default configuration.
func (*DynamoComponent) Settings() *DynamoConfig {
	return &DynamoConfig{
		TableName:    defaultTableName,
		PartitionKey: defaultPartitionKey,
		TTLKey:       deafultTTLKey,
	}
}

// New constructs the component.
func (*DynamoComponent) New(ctx context.Context, conf *DynamoConfig) (domain.Store, error) {
	awsConfig := aws.NewConfig()
	awsConfig.Region = aws.String(conf.Region)
	awsConfig.Endpoint = aws.String(conf.Endpoint)
	awsSession, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}

	client := dynamodb.New(awsSession)
	return &DynamoDB{
		Client:           client,
		TableName:        conf.TableName,
		PartitionKeyName: conf.PartitionKey,
		TTLKeyName:       conf.TTLKey,
	}, nil
}
