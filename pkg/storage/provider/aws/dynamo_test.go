package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamotypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/nckslvrmn/secure_secret_share/pkg/simple_crypt"
	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
)

// MockDynamoClient implements DynamoDBAPI
type MockDynamoClient struct {
	getItem    func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	putItem    func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	deleteItem func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	updateItem func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

func (m *MockDynamoClient) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if m.getItem != nil {
		return m.getItem(ctx, params, optFns...)
	}
	return nil, errors.New("GetItem not implemented")
}

func (m *MockDynamoClient) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if m.putItem != nil {
		return m.putItem(ctx, params, optFns...)
	}
	return nil, errors.New("PutItem not implemented")
}

func (m *MockDynamoClient) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	if m.deleteItem != nil {
		return m.deleteItem(ctx, params, optFns...)
	}
	return nil, errors.New("DeleteItem not implemented")
}

func (m *MockDynamoClient) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if m.updateItem != nil {
		return m.updateItem(ctx, params, optFns...)
	}
	return nil, errors.New("UpdateItem not implemented")
}

func TestDynamoStore_StoreSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  *simple_crypt.Secret
		mockFn  func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
		wantErr bool
	}{
		{
			name: "successful store",
			secret: &simple_crypt.Secret{
				SecretId:  "test-id",
				Data:      []byte("test data"),
				ViewCount: 3,
				TTL:       time.Now().Unix() + 3600,
				IsFile:    false,
				Nonce:     []byte("test nonce"),
				Salt:      []byte("test salt"),
				Header:    []byte("test header"),
			},
			mockFn: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
				if params.TableName == nil || *params.TableName != utils.DynamoTable {
					return nil, errors.New("invalid table name")
				}
				return &dynamodb.PutItemOutput{}, nil
			},
			wantErr: false,
		},
		{
			name: "dynamo error",
			secret: &simple_crypt.Secret{
				SecretId: "test-id",
			},
			mockFn: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
				return nil, errors.New("dynamo error")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &DynamoStore{
				client: &MockDynamoClient{
					putItem: tt.mockFn,
				},
			}

			err := store.StoreSecret(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("StoreSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDynamoStore_GetSecret(t *testing.T) {
	tests := []struct {
		name     string
		secretId string
		mockFn   func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
		want     *simple_crypt.Secret
		wantErr  bool
	}{
		{
			name:     "successful get",
			secretId: "test-id",
			mockFn: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
				return &dynamodb.GetItemOutput{
					Item: map[string]dynamotypes.AttributeValue{
						"secret_id":  &dynamotypes.AttributeValueMemberS{Value: "test-id"},
						"view_count": &dynamotypes.AttributeValueMemberN{Value: "3"},
						"data":       &dynamotypes.AttributeValueMemberS{Value: utils.B64E([]byte("test data"))},
						"is_file":    &dynamotypes.AttributeValueMemberBOOL{Value: false},
						"nonce":      &dynamotypes.AttributeValueMemberS{Value: utils.B64E([]byte("test nonce"))},
						"salt":       &dynamotypes.AttributeValueMemberS{Value: utils.B64E([]byte("test salt"))},
						"header":     &dynamotypes.AttributeValueMemberS{Value: utils.B64E([]byte("test header"))},
					},
				}, nil
			},
			want: &simple_crypt.Secret{
				SecretId:  "test-id",
				ViewCount: 3,
				Data:      []byte("test data"),
				IsFile:    false,
				Nonce:     []byte("test nonce"),
				Salt:      []byte("test salt"),
				Header:    []byte("test header"),
			},
			wantErr: false,
		},
		{
			name:     "secret not found",
			secretId: "non-existent",
			mockFn: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
				return &dynamodb.GetItemOutput{
					Item: nil,
				}, nil
			},
			want:    nil,
			wantErr: true,
		},
		{
			name:     "dynamo error",
			secretId: "test-id",
			mockFn: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
				return nil, errors.New("dynamo error")
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &DynamoStore{
				client: &MockDynamoClient{
					getItem: tt.mockFn,
				},
			}

			got, err := store.GetSecret(tt.secretId)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != nil {
				if got.SecretId != tt.want.SecretId {
					t.Errorf("GetSecret() SecretId = %v, want %v", got.SecretId, tt.want.SecretId)
				}
				if got.ViewCount != tt.want.ViewCount {
					t.Errorf("GetSecret() ViewCount = %v, want %v", got.ViewCount, tt.want.ViewCount)
				}
			}
		})
	}
}

func TestDynamoStore_DeleteSecret(t *testing.T) {
	tests := []struct {
		name     string
		secretId string
		mockFn   func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
		wantErr  bool
	}{
		{
			name:     "successful delete",
			secretId: "test-id",
			mockFn: func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
				if params.TableName == nil || *params.TableName != utils.DynamoTable {
					return nil, errors.New("invalid table name")
				}
				return &dynamodb.DeleteItemOutput{}, nil
			},
			wantErr: false,
		},
		{
			name:     "dynamo error",
			secretId: "test-id",
			mockFn: func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
				return nil, errors.New("dynamo error")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &DynamoStore{
				client: &MockDynamoClient{
					deleteItem: tt.mockFn,
				},
			}

			err := store.DeleteSecret(tt.secretId)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDynamoStore_UpdateSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  *simple_crypt.Secret
		mockFn  func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
		wantErr bool
	}{
		{
			name: "successful update",
			secret: &simple_crypt.Secret{
				SecretId:  "test-id",
				ViewCount: 5,
			},
			mockFn: func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
				if params.TableName == nil || *params.TableName != utils.DynamoTable {
					return nil, errors.New("invalid table name")
				}
				return &dynamodb.UpdateItemOutput{}, nil
			},
			wantErr: false,
		},
		{
			name: "dynamo error",
			secret: &simple_crypt.Secret{
				SecretId: "test-id",
			},
			mockFn: func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
				return nil, errors.New("dynamo error")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &DynamoStore{
				client: &MockDynamoClient{
					updateItem: tt.mockFn,
				},
			}

			err := store.UpdateSecret(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
