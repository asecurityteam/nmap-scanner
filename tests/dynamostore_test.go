// +build integration

package tests

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
	"github.com/asecurityteam/nmap-scanner/pkg/store"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/stretchr/testify/require"
)

func TestDynamoStore(t *testing.T) {
	tableName := os.Getenv("DYNAMO_TABLE_NAME") + fmt.Sprintf("%d", rand.Int63())
	partitionKey := os.Getenv("DYNAMO_TABLE_PARTITIONKEY")
	ttlKey := os.Getenv("DYNAMO_TABLE_TTLKEY")
	region := os.Getenv("DYNAMO_TABLE_REGION")
	endpoint := os.Getenv("DYNAMO_TABLE_ENDPOINT")

	// Bootstrap a dynamo table for the tests.
	awsConfig := aws.NewConfig()
	awsConfig.Region = aws.String(region)
	awsConfig.Endpoint = aws.String(endpoint)
	awsSession, err := session.NewSession(awsConfig)
	require.Nil(t, err)
	client := dynamodb.New(awsSession)
	start := time.Now()
	for time.Since(start) < 10*time.Second {
		_, err = client.CreateTable(&dynamodb.CreateTableInput{
			AttributeDefinitions: []*dynamodb.AttributeDefinition{
				&dynamodb.AttributeDefinition{
					AttributeName: aws.String(partitionKey),
					AttributeType: aws.String("S"),
				},
			},
			KeySchema: []*dynamodb.KeySchemaElement{
				&dynamodb.KeySchemaElement{
					AttributeName: aws.String(partitionKey),
					KeyType:       aws.String("HASH"),
				},
			},
			TableName: aws.String(tableName),
			ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(10),
				WriteCapacityUnits: aws.Int64(10),
			},
		})
		if err == nil {
			break
		}
		t.Log(err)
	}
	require.Nil(t, err)

	cmp := store.NewDynamoComponent()
	ctx := context.Background()
	id := "test"

	conf := cmp.Settings()
	conf.TableName = tableName
	conf.PartitionKey = partitionKey
	conf.TTLKey = ttlKey
	conf.AWS.Session.Region = region
	conf.AWS.Session.Endpoint = endpoint
	s, err := cmp.New(ctx, conf)
	require.Nil(t, err)
	require.NotNil(t, s)

	_, err = s.Load(ctx, id)
	require.NotNil(t, err)
	require.IsType(t, domain.NotFoundError{}, err, err.Error())

	err = s.Mark(ctx, id)
	require.Nil(t, err)
	_, err = s.Load(ctx, id)
	require.NotNil(t, err)
	require.IsType(t, domain.InProgressError{}, err, err.Error())

	expected := []domain.Finding{
		{
			Timestamp: time.Now().UTC(),
			Vulnerabilities: []domain.Vulnerability{
				domain.Vulnerability{
					Key:            "TESTVULN",
					State:          domain.VulnStateNot,
					IDs:            []domain.VulnerabilityID{},
					Scores:         []domain.VulnerabilityScore{},
					Dates:          []domain.VulnerabilityDate{},
					CheckResults:   []string{},
					ExploitResults: []string{},
					ExtraInfo:      []string{},
					References:     []string{},
				},
			},
		},
	}
	err = s.Set(ctx, id, expected)
	require.Nil(t, err)
	r, err := s.Load(ctx, id)
	require.Nil(t, err)
	require.Equal(t, expected, r)
}
