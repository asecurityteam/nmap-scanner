package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	awscmp "github.com/asecurityteam/component-aws"
	"github.com/asecurityteam/nmap-scanner/pkg/domain"
	"github.com/aws/aws-sdk-go/aws"
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

// vulnerability is a JSON domain.Vulnerability.
type vulnerability struct {
	Key            string
	Title          string
	State          string
	IDs            []vulnerabilityID
	RiskFactor     string
	Scores         []vulnerabilityScore
	Description    string
	Dates          []vulnerabilityDate
	CheckResults   []string
	ExploitResults []string
	ExtraInfo      []string
	References     []string

	Source   string
	Port     int
	Protocol string
	Service  string
}

// vulnerabilityDate is a JSON domain.VulnerabilityDate.
type vulnerabilityDate struct {
	Type  string
	Year  int
	Month int
	Day   int
}

// vulnerabilityScore is a JSON domain.VulnerabilityScore.
type vulnerabilityScore struct {
	Type  string
	Value string
}

// vulnerabilityID is a JSON domain.VulnerabilityID.
type vulnerabilityID struct {
	Type  string
	Value string
}

// finding is a JSON domain.Finding.
type finding struct {
	// Timestamp is when the finding was detected.
	Timestamp time.Time
	// IP is the address that was scanned.
	IP string
	// Hostnames are optionally included names that resolve to the scan IP.
	Hostnames       []string
	Vulnerabilities []vulnerability
}

func vulnerabilityFromDomain(source domain.Vulnerability) vulnerability {
	v := vulnerability{
		Key:            source.Key,
		Title:          source.Title,
		State:          source.State,
		IDs:            make([]vulnerabilityID, 0, len(source.IDs)),
		RiskFactor:     source.RiskFactor,
		Scores:         make([]vulnerabilityScore, 0, len(source.Scores)),
		Description:    source.Description,
		Dates:          make([]vulnerabilityDate, 0, len(source.Dates)),
		CheckResults:   source.CheckResults,
		ExploitResults: source.ExploitResults,
		ExtraInfo:      source.ExtraInfo,
		References:     source.References,
		Source:         source.Source,
		Port:           source.Port,
		Protocol:       source.Protocol,
		Service:        source.Service,
	}
	for _, id := range source.IDs {
		v.IDs = append(v.IDs, vulnerabilityID(id))
	}
	for _, score := range source.Scores {
		v.Scores = append(v.Scores, vulnerabilityScore(score))
	}
	for _, date := range source.Dates {
		v.Dates = append(v.Dates, vulnerabilityDate(date))
	}

	return v
}

func findingFromDomain(source domain.Finding) finding {
	f := finding{
		Timestamp:       source.Timestamp,
		IP:              source.IP,
		Hostnames:       source.Hostnames,
		Vulnerabilities: make([]vulnerability, 0, len(source.Vulnerabilities)),
	}
	for _, v := range source.Vulnerabilities {
		f.Vulnerabilities = append(f.Vulnerabilities, vulnerabilityFromDomain(v))
	}
	return f
}

func vulnerabilityToDomain(source vulnerability) domain.Vulnerability {
	v := domain.Vulnerability{
		Key:            source.Key,
		Title:          source.Title,
		State:          source.State,
		IDs:            make([]domain.VulnerabilityID, 0, len(source.IDs)),
		RiskFactor:     source.RiskFactor,
		Scores:         make([]domain.VulnerabilityScore, 0, len(source.Scores)),
		Description:    source.Description,
		Dates:          make([]domain.VulnerabilityDate, 0, len(source.Dates)),
		CheckResults:   source.CheckResults,
		ExploitResults: source.ExploitResults,
		ExtraInfo:      source.ExtraInfo,
		References:     source.References,
		Source:         source.Source,
		Port:           source.Port,
		Protocol:       source.Protocol,
		Service:        source.Service,
	}
	for _, id := range source.IDs {
		v.IDs = append(v.IDs, domain.VulnerabilityID(id))
	}
	for _, score := range source.Scores {
		v.Scores = append(v.Scores, domain.VulnerabilityScore(score))
	}
	for _, date := range source.Dates {
		v.Dates = append(v.Dates, domain.VulnerabilityDate(date))
	}

	return v
}

func findingToDomain(source finding) domain.Finding {
	f := domain.Finding{
		Timestamp:       source.Timestamp,
		IP:              source.IP,
		Hostnames:       source.Hostnames,
		Vulnerabilities: make([]domain.Vulnerability, 0, len(source.Vulnerabilities)),
	}
	for _, v := range source.Vulnerabilities {
		f.Vulnerabilities = append(f.Vulnerabilities, vulnerabilityToDomain(v))
	}
	return f
}

func toDomain(source []finding) []domain.Finding {
	r := make([]domain.Finding, 0, len(source))
	for _, s := range source {
		r = append(r, findingToDomain(s))
	}
	return r
}

func fromDomain(source []domain.Finding) []finding {
	r := make([]finding, 0, len(source))
	for _, s := range source {
		r = append(r, findingFromDomain(s))
	}
	return r
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
func (s *DynamoDB) Set(ctx context.Context, identifier string, findings []domain.Finding) error {
	b, _ := json.Marshal(fromDomain(findings))
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
func (s *DynamoDB) Load(ctx context.Context, identifier string) ([]domain.Finding, error) {
	item, err := s.Client.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.TableName),
		Key: map[string]*dynamodb.AttributeValue{
			s.PartitionKeyName: {
				S: aws.String(identifier),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch result: %v", err)
	}

	var result dynamoResult
	err = dynamodbattribute.UnmarshalMap(item.Item, &result)
	if err == nil && len(item.Item) > 0 {
		var f []finding
		err = json.Unmarshal([]byte(result.Data), &f)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal result: %v,", err)
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
		return nil, fmt.Errorf("failed to fetch marker: %v", err)
	}
	err = dynamodbattribute.UnmarshalMap(item.Item, &result)
	if err == nil && result.Data == marker {
		return nil, domain.InProgressError{Identifier: identifier}
	}
	return nil, domain.NotFoundError{Identifier: identifier}
}

// DynamoConf wraps the original config to add a name.
type DynamoConf struct {
	*awscmp.DynamoDBConfig
}

// Name of the configuration root.
func (*DynamoConf) Name() string {
	return "aws"
}

// DynamoConfig contains all settings for the in-memory component.
type DynamoConfig struct {
	TableName    string `description:"The name of the DynamoDB table to use."`
	PartitionKey string `description:"Name of the table partition key."`
	TTLKey       string `description:"Name of the TTL key."`
	AWS          *DynamoConf
}

// Name of the configuration root.
func (*DynamoConfig) Name() string {
	return "dynamodb"
}

// DynamoComponent implements the component interface for the in-memory option.
type DynamoComponent struct {
	DynamoDB *awscmp.DynamoDBComponent
}

// NewDynamoComponent constructs a default DynamoComponent.
func NewDynamoComponent() *DynamoComponent {
	return &DynamoComponent{
		DynamoDB: awscmp.NewDynamoDBComponent(),
	}
}

// Settings returns the default configuration.
func (c *DynamoComponent) Settings() *DynamoConfig {
	return &DynamoConfig{
		TableName:    defaultTableName,
		PartitionKey: defaultPartitionKey,
		TTLKey:       deafultTTLKey,
		AWS:          &DynamoConf{c.DynamoDB.Settings()},
	}
}

// New constructs the component.
func (c *DynamoComponent) New(ctx context.Context, conf *DynamoConfig) (domain.Store, error) {
	client, err := c.DynamoDB.New(ctx, conf.AWS.DynamoDBConfig)
	if err != nil {
		return nil, err
	}
	return &DynamoDB{
		Client:           client,
		TableName:        conf.TableName,
		PartitionKeyName: conf.PartitionKey,
		TTLKeyName:       conf.TTLKey,
	}, nil
}
