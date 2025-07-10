package aws

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamotypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/nckslvrmn/secure_secret_share/pkg/simple_crypt"
	storagetypes "github.com/nckslvrmn/secure_secret_share/pkg/storage/types"
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
	cfg, _ := config.LoadDefaultConfig(context.TODO(), config.WithRegion(utils.AWSRegion))
	return &DynamoStore{
		client: dynamodb.NewFromConfig(cfg),
	}
}

func (d *DynamoStore) StoreSecret(s *simple_crypt.Secret) error {
	item := map[string]dynamotypes.AttributeValue{
		"secret_id":  &dynamotypes.AttributeValueMemberS{Value: s.SecretId},
		"view_count": &dynamotypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", s.ViewCount)},
		"data":       &dynamotypes.AttributeValueMemberS{Value: utils.B64E(s.Data)},
		"is_file":    &dynamotypes.AttributeValueMemberBOOL{Value: s.IsFile},
		"nonce":      &dynamotypes.AttributeValueMemberS{Value: utils.B64E(s.Nonce)},
		"salt":       &dynamotypes.AttributeValueMemberS{Value: utils.B64E(s.Salt)},
		"header":     &dynamotypes.AttributeValueMemberS{Value: utils.B64E(s.Header)},
		"ttl":        &dynamotypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", s.TTL)},
	}

	_, err := d.client.PutItem(
		context.TODO(),
		&dynamodb.PutItemInput{
			TableName: aws.String(utils.DynamoTable),
			Item:      item,
		},
	)

	return err
}

func (d *DynamoStore) GetSecret(secretId string) (*simple_crypt.Secret, error) {
	result, err := d.client.GetItem(
		context.TODO(),
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

	secret := &simple_crypt.Secret{
		SecretId: secretId,
	}

	if v, ok := result.Item["view_count"].(*dynamotypes.AttributeValueMemberN); ok {
		viewCount, err := strconv.Atoi(v.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid view count: %w", err)
		}
		secret.ViewCount = viewCount
	}

	if v, ok := result.Item["is_file"].(*dynamotypes.AttributeValueMemberBOOL); ok {
		secret.IsFile = v.Value
	}

	if v, ok := result.Item["data"].(*dynamotypes.AttributeValueMemberS); ok {
		data, err := utils.B64D(v.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid data encoding: %w", err)
		}
		secret.Data = data
	}

	if v, ok := result.Item["nonce"].(*dynamotypes.AttributeValueMemberS); ok {
		nonce, err := utils.B64D(v.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid nonce encoding: %w", err)
		}
		secret.Nonce = nonce
	}

	if v, ok := result.Item["salt"].(*dynamotypes.AttributeValueMemberS); ok {
		salt, err := utils.B64D(v.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid salt encoding: %w", err)
		}
		secret.Salt = salt
	}

	if v, ok := result.Item["header"].(*dynamotypes.AttributeValueMemberS); ok {
		header, err := utils.B64D(v.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid header encoding: %w", err)
		}
		secret.Header = header
	}

	return secret, nil
}

func (d *DynamoStore) DeleteSecret(secretId string) error {
	_, err := d.client.DeleteItem(
		context.TODO(),
		&dynamodb.DeleteItemInput{
			TableName: aws.String(utils.DynamoTable),
			Key: map[string]dynamotypes.AttributeValue{
				"secret_id": &dynamotypes.AttributeValueMemberS{Value: secretId},
			},
		},
	)
	return err
}

func (d *DynamoStore) UpdateSecret(s *simple_crypt.Secret) error {
	_, err := d.client.UpdateItem(
		context.TODO(),
		&dynamodb.UpdateItemInput{
			TableName: aws.String(utils.DynamoTable),
			Key: map[string]dynamotypes.AttributeValue{
				"secret_id": &dynamotypes.AttributeValueMemberS{Value: s.SecretId},
			},
			UpdateExpression: aws.String("SET view_count = :val"),
			ExpressionAttributeValues: map[string]dynamotypes.AttributeValue{
				":val": &dynamotypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", s.ViewCount)},
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to update view count for secret: %w", err)
	}

	return nil
}
