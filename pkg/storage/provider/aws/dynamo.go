package aws

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamotypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/nckslvrmn/go_ots/pkg/simple_crypt"
	storagetypes "github.com/nckslvrmn/go_ots/pkg/storage/types"
	"github.com/nckslvrmn/go_ots/pkg/utils"
)

type DynamoStore struct {
	client *dynamodb.Client
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
	result, _ := d.client.GetItem(
		context.TODO(),
		&dynamodb.GetItemInput{
			TableName: aws.String(utils.DynamoTable),
			Key: map[string]dynamotypes.AttributeValue{
				"secret_id": &dynamotypes.AttributeValueMemberS{Value: secretId},
			},
		},
	)

	if result.Item == nil {
		return nil, fmt.Errorf("secret not found")
	}

	secret := &simple_crypt.Secret{
		SecretId: secretId,
	}

	if v, ok := result.Item["view_count"].(*dynamotypes.AttributeValueMemberN); ok {
		secret.ViewCount, _ = strconv.Atoi(v.Value)
	}

	if v, ok := result.Item["is_file"].(*dynamotypes.AttributeValueMemberBOOL); ok {
		secret.IsFile = v.Value
	}

	if v, ok := result.Item["data"].(*dynamotypes.AttributeValueMemberS); ok {
		secret.Data, _ = utils.B64D(v.Value)
	}

	if v, ok := result.Item["nonce"].(*dynamotypes.AttributeValueMemberS); ok {
		secret.Nonce, _ = utils.B64D(v.Value)
	}

	if v, ok := result.Item["salt"].(*dynamotypes.AttributeValueMemberS); ok {
		secret.Salt, _ = utils.B64D(v.Value)
	}

	if v, ok := result.Item["header"].(*dynamotypes.AttributeValueMemberS); ok {
		secret.Header, _ = utils.B64D(v.Value)
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
