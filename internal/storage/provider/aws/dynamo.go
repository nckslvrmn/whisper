package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamotypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/nckslvrmn/whisper/internal/config"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
)

type DynamoDBAPI interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// errRaced means a concurrent request changed the counter between our
// conditional delete and our conditional decrement.
var errRaced = errors.New("view consumption raced")

type DynamoStore struct {
	client DynamoDBAPI
}

func NewDynamoStore() storagetypes.SecretStore {
	cfg, _ := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(config.AWSRegion))
	return &DynamoStore{
		client: dynamodb.NewFromConfig(cfg),
	}
}

func (d *DynamoStore) key(id string) map[string]dynamotypes.AttributeValue {
	return map[string]dynamotypes.AttributeValue{
		"secret_id": &dynamotypes.AttributeValueMemberS{Value: id},
	}
}

func (d *DynamoStore) StoreSecret(ctx context.Context, id string, payload []byte, ttl *int64, viewCount *int) error {
	item := map[string]dynamotypes.AttributeValue{
		"secret_id": &dynamotypes.AttributeValueMemberS{Value: id},
		"data":      &dynamotypes.AttributeValueMemberS{Value: string(payload)},
	}

	if viewCount != nil && *viewCount > 0 {
		item["view_count"] = &dynamotypes.AttributeValueMemberN{Value: strconv.Itoa(*viewCount)}
	}

	if ttl != nil {
		item["ttl"] = &dynamotypes.AttributeValueMemberN{Value: strconv.FormatInt(*ttl, 10)}
	}

	_, err := d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(config.DynamoTable),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	return nil
}

func (d *DynamoStore) GetSecret(ctx context.Context, id string) ([]byte, *int64, error) {
	result, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(config.DynamoTable),
		Key:       d.key(id),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if result.Item == nil {
		return nil, nil, storagetypes.ErrNotFound
	}

	stored, ok := result.Item["data"].(*dynamotypes.AttributeValueMemberS)
	if !ok {
		return nil, nil, fmt.Errorf("data field not found")
	}

	payload, err := storagetypes.DecodeStoredPayload(stored.Value)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid data encoding: %w", err)
	}

	return payload, numberAttr(result.Item, "ttl"), nil
}

// ConsumeView never writes a 0 into view_count: the last view is a conditional
// delete, so a stored 0 can only be legacy data and always means unlimited.
func (d *DynamoStore) ConsumeView(ctx context.Context, id string) (int, error) {
	remaining, err := d.consumeOnce(ctx, id)
	if !errors.Is(err, errRaced) {
		return remaining, err
	}

	remaining, err = d.consumeOnce(ctx, id)
	if errors.Is(err, errRaced) {
		return 0, storagetypes.ErrNotFound
	}
	return remaining, err
}

func (d *DynamoStore) consumeOnce(ctx context.Context, id string) (int, error) {
	one := &dynamotypes.AttributeValueMemberN{Value: "1"}

	_, err := d.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(config.DynamoTable),
		Key:                       d.key(id),
		ConditionExpression:       aws.String("view_count = :one"),
		ExpressionAttributeValues: map[string]dynamotypes.AttributeValue{":one": one},
	})
	if err == nil {
		return 0, nil
	}
	if !isConditionalCheckFailed(err) {
		return 0, fmt.Errorf("failed to consume last view: %w", err)
	}

	updated, err := d.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(config.DynamoTable),
		Key:                       d.key(id),
		UpdateExpression:          aws.String("SET view_count = view_count - :one"),
		ConditionExpression:       aws.String("view_count > :one"),
		ExpressionAttributeValues: map[string]dynamotypes.AttributeValue{":one": one},
		ReturnValues:              dynamotypes.ReturnValueUpdatedNew,
	})
	if err == nil {
		remaining, present, err := viewCountAttr(updated.Attributes)
		if err != nil {
			return 0, err
		}
		if !present {
			return 0, fmt.Errorf("update did not return view_count")
		}
		return remaining, nil
	}
	if !isConditionalCheckFailed(err) {
		return 0, fmt.Errorf("failed to consume view: %w", err)
	}

	result, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(config.DynamoTable),
		Key:            d.key(id),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to classify view count: %w", err)
	}
	if result.Item == nil {
		return 0, storagetypes.ErrNotFound
	}

	viewCount, present, err := viewCountAttr(result.Item)
	if err != nil {
		return 0, err
	}
	if !present || viewCount == 0 {
		return storagetypes.UnlimitedViews, nil
	}
	return 0, errRaced
}

func (d *DynamoStore) DeleteSecret(ctx context.Context, id string) error {
	_, err := d.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(config.DynamoTable),
		Key:       d.key(id),
	})
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}

func isConditionalCheckFailed(err error) bool {
	var cond *dynamotypes.ConditionalCheckFailedException
	return errors.As(err, &cond)
}

// Parsing straight to int avoids narrowing from int64. An absent attribute
// means unlimited views, but an out-of-range one is corrupt and fails closed.
func viewCountAttr(item map[string]dynamotypes.AttributeValue) (count int, present bool, err error) {
	attr, ok := item["view_count"].(*dynamotypes.AttributeValueMemberN)
	if !ok {
		return 0, false, nil
	}

	count, err = strconv.Atoi(attr.Value)
	if err != nil {
		return 0, true, fmt.Errorf("invalid view_count attribute %q: %w", attr.Value, err)
	}
	return count, true, nil
}

func numberAttr(item map[string]dynamotypes.AttributeValue, name string) *int64 {
	attr, ok := item[name].(*dynamotypes.AttributeValueMemberN)
	if !ok {
		return nil
	}
	value, err := strconv.ParseInt(attr.Value, 10, 64)
	if err != nil {
		return nil
	}
	return &value
}
