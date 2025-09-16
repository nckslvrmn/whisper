package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamotypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	storagetypes "github.com/nckslvrmn/secure_secret_share/internal/storage/types"
	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
)

// DynamoDBAPI defines the interface for DynamoDB operations we use
type DynamoDBAPI interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

type DynamoStore struct {
	client DynamoDBAPI
}

func NewDynamoStore() storagetypes.SecretStore {
	cfg, _ := config.LoadDefaultConfig(context.Background(), config.WithRegion(utils.AWSRegion))
	return &DynamoStore{
		client: dynamodb.NewFromConfig(cfg),
	}
}

func (d *DynamoStore) StoreSecretRaw(secretId string, data []byte, ttl int64, viewCount int) error {
	item := map[string]dynamotypes.AttributeValue{
		"secret_id":  &dynamotypes.AttributeValueMemberS{Value: secretId},
		"view_count": &dynamotypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", viewCount)},
		"data":       &dynamotypes.AttributeValueMemberS{Value: utils.B64E(data)},
		"ttl":        &dynamotypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", ttl)},
	}

	_, err := d.client.PutItem(
		context.Background(),
		&dynamodb.PutItemInput{
			TableName: aws.String(utils.DynamoTable),
			Item:      item,
		},
	)

	return err
}

func (d *DynamoStore) GetSecretRaw(secretId string) ([]byte, error) {
	result, err := d.client.GetItem(
		context.Background(),
		&dynamodb.GetItemInput{
			TableName: aws.String(utils.DynamoTable),
			Key: map[string]dynamotypes.AttributeValue{
				"secret_id": &dynamotypes.AttributeValueMemberS{Value: secretId},
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if result.Item == nil {
		return nil, fmt.Errorf("secret not found")
	}

	if v, ok := result.Item["data"].(*dynamotypes.AttributeValueMemberS); ok {
		data, err := utils.B64D(v.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid data encoding: %w", err)
		}
		return data, nil
	}

	return nil, fmt.Errorf("data field not found")
}

func (d *DynamoStore) DeleteSecret(secretId string) error {
	_, err := d.client.DeleteItem(
		context.Background(),
		&dynamodb.DeleteItemInput{
			TableName: aws.String(utils.DynamoTable),
			Key: map[string]dynamotypes.AttributeValue{
				"secret_id": &dynamotypes.AttributeValueMemberS{Value: secretId},
			},
		},
	)
	return err
}

func (d *DynamoStore) UpdateSecretRaw(secretId string, data []byte) error {
	_, err := d.client.UpdateItem(
		context.Background(),
		&dynamodb.UpdateItemInput{
			TableName: aws.String(utils.DynamoTable),
			Key: map[string]dynamotypes.AttributeValue{
				"secret_id": &dynamotypes.AttributeValueMemberS{Value: secretId},
			},
			UpdateExpression: aws.String("SET #data = :val"),
			ExpressionAttributeNames: map[string]string{
				"#data": "data",
			},
			ExpressionAttributeValues: map[string]dynamotypes.AttributeValue{
				":val": &dynamotypes.AttributeValueMemberS{Value: utils.B64E(data)},
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}
