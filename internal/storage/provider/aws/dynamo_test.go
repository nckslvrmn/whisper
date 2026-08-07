package aws

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamotypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/nckslvrmn/whisper/internal/config"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
	"github.com/nckslvrmn/whisper/pkg/utils"
)

// fakeDynamo implements the exact conditional operations DynamoStore issues.
type fakeDynamo struct {
	items map[string]map[string]dynamotypes.AttributeValue

	// condFailDelete and condFailUpdate force the conditional op to report a
	// failed check regardless of the stored counter, which is what a lost race
	// looks like to the caller.
	condFailDelete bool
	condFailUpdate bool
	beforeUpdate   func()

	getCalls int
}

func newFakeDynamo() *fakeDynamo {
	return &fakeDynamo{items: map[string]map[string]dynamotypes.AttributeValue{}}
}

func itemKey(key map[string]dynamotypes.AttributeValue) string {
	return key["secret_id"].(*dynamotypes.AttributeValueMemberS).Value
}

func (f *fakeDynamo) viewCount(id string) (int64, bool) {
	attr, ok := f.items[id]["view_count"].(*dynamotypes.AttributeValueMemberN)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(attr.Value, 10, 64)
	return n, err == nil
}

func (f *fakeDynamo) setViewCount(id string, n int64) {
	f.items[id]["view_count"] = &dynamotypes.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}

func (f *fakeDynamo) GetItem(ctx context.Context, params *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.getCalls++
	return &dynamodb.GetItemOutput{Item: f.items[itemKey(params.Key)]}, nil
}

func (f *fakeDynamo) PutItem(ctx context.Context, params *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.items[itemKey(params.Item)] = params.Item
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamo) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	id := itemKey(params.Key)

	if params.ConditionExpression != nil {
		count, ok := f.viewCount(id)
		if f.condFailDelete || !ok || count != 1 {
			return nil, &dynamotypes.ConditionalCheckFailedException{}
		}
	}

	delete(f.items, id)
	return &dynamodb.DeleteItemOutput{}, nil
}

func (f *fakeDynamo) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if f.beforeUpdate != nil {
		hook := f.beforeUpdate
		f.beforeUpdate = nil
		hook()
	}

	id := itemKey(params.Key)
	count, ok := f.viewCount(id)
	if f.condFailUpdate || !ok || count <= 1 {
		return nil, &dynamotypes.ConditionalCheckFailedException{}
	}

	f.setViewCount(id, count-1)
	return &dynamodb.UpdateItemOutput{Attributes: map[string]dynamotypes.AttributeValue{
		"view_count": f.items[id]["view_count"],
	}}, nil
}

func newTestDynamoStore(t *testing.T) (*DynamoStore, *fakeDynamo) {
	t.Helper()
	config.DynamoTable = "test-table"
	fake := newFakeDynamo()
	return &DynamoStore{client: fake}, fake
}

func ptrInt(n int) *int { return &n }

// --- StoreSecret / GetSecret ---

func TestDynamo_StoreAndGetSecret(t *testing.T) {
	store, fake := newTestDynamoStore(t)
	ctx := context.Background()

	ttl := int64(1893456000)
	payload := []byte(`{"passwordHash":"abc"}`)
	if err := store.StoreSecret(ctx, "abcdefghijklmnop", payload, &ttl, ptrInt(3)); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	stored := fake.items["abcdefghijklmnop"]["data"].(*dynamotypes.AttributeValueMemberS).Value
	if stored != string(payload) {
		t.Errorf("stored data = %q, want raw JSON %q", stored, payload)
	}

	got, gotTTL, err := store.GetSecret(ctx, "abcdefghijklmnop")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if gotTTL == nil || *gotTTL != ttl {
		t.Errorf("ttl = %v, want %d", gotTTL, ttl)
	}
}

func TestDynamo_StoreSecret_UnlimitedOmitsViewCount(t *testing.T) {
	store, fake := newTestDynamoStore(t)

	if err := store.StoreSecret(context.Background(), "unlimited1234567", []byte(`{}`), nil, ptrInt(0)); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	if _, ok := fake.items["unlimited1234567"]["view_count"]; ok {
		t.Error("view_count attribute must be absent for unlimited secrets")
	}
}

func TestDynamo_GetSecret_NotFound(t *testing.T) {
	store, _ := newTestDynamoStore(t)

	_, _, err := store.GetSecret(context.Background(), "missing123456789")
	if !errors.Is(err, storagetypes.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDynamo_GetSecret_LegacyBase64Payload(t *testing.T) {
	store, fake := newTestDynamoStore(t)

	payload := []byte(`{"passwordHash":"abc","viewCount":2}`)
	fake.items["legacyblob123456"] = map[string]dynamotypes.AttributeValue{
		"secret_id": &dynamotypes.AttributeValueMemberS{Value: "legacyblob123456"},
		"data":      &dynamotypes.AttributeValueMemberS{Value: utils.B64E(payload)},
	}

	got, _, err := store.GetSecret(context.Background(), "legacyblob123456")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

// --- ConsumeView ---

func TestDynamo_ConsumeView_Decrements(t *testing.T) {
	store, fake := newTestDynamoStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "consume123456789", []byte(`{}`), nil, ptrInt(3))

	remaining, err := store.ConsumeView(ctx, "consume123456789")
	if err != nil || remaining != 2 {
		t.Fatalf("remaining = %d, err = %v", remaining, err)
	}
	if count, _ := fake.viewCount("consume123456789"); count != 2 {
		t.Errorf("stored view_count = %d, want 2", count)
	}
}

func TestDynamo_ConsumeView_LastViewDeletesItem(t *testing.T) {
	store, fake := newTestDynamoStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "lastview12345678", []byte(`{}`), nil, ptrInt(1))

	remaining, err := store.ConsumeView(ctx, "lastview12345678")
	if err != nil || remaining != 0 {
		t.Fatalf("remaining = %d, err = %v", remaining, err)
	}
	if _, ok := fake.items["lastview12345678"]; ok {
		t.Error("item should be deleted on the last view")
	}
}

func TestDynamo_ConsumeView_Unlimited(t *testing.T) {
	store, _ := newTestDynamoStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "nolimit123456789", []byte(`{}`), nil, nil)

	remaining, err := store.ConsumeView(ctx, "nolimit123456789")
	if err != nil {
		t.Fatalf("ConsumeView: %v", err)
	}
	if remaining != storagetypes.UnlimitedViews {
		t.Errorf("remaining = %d, want UnlimitedViews", remaining)
	}
}

func TestDynamo_ConsumeView_LegacyZeroMeansUnlimited(t *testing.T) {
	store, fake := newTestDynamoStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "legacyzero123456", []byte(`{}`), nil, nil)
	fake.setViewCount("legacyzero123456", 0)

	remaining, err := store.ConsumeView(ctx, "legacyzero123456")
	if err != nil {
		t.Fatalf("ConsumeView: %v", err)
	}
	if remaining != storagetypes.UnlimitedViews {
		t.Errorf("remaining = %d, want UnlimitedViews", remaining)
	}
}

func TestDynamo_ConsumeView_Missing(t *testing.T) {
	store, _ := newTestDynamoStore(t)

	if _, err := store.ConsumeView(context.Background(), "missing123456789"); !errors.Is(err, storagetypes.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// A concurrent request that drops the counter to 1 between our two conditional
// ops is retried, and the retry consumes the last view.
func TestDynamo_ConsumeView_RetriesLostRace(t *testing.T) {
	store, fake := newTestDynamoStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "racedonce1234567", []byte(`{}`), nil, ptrInt(2))
	fake.beforeUpdate = func() { fake.setViewCount("racedonce1234567", 1) }

	remaining, err := store.ConsumeView(ctx, "racedonce1234567")
	if err != nil || remaining != 0 {
		t.Fatalf("remaining = %d, err = %v", remaining, err)
	}
	if _, ok := fake.items["racedonce1234567"]; ok {
		t.Error("item should be deleted by the retry")
	}
}

// Losing the race twice denies the request rather than over-consuming.
func TestDynamo_ConsumeView_PersistentRaceReturnsNotFound(t *testing.T) {
	store, fake := newTestDynamoStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "racedtwice123456", []byte(`{}`), nil, ptrInt(1))
	fake.condFailDelete = true
	fake.condFailUpdate = true

	if _, err := store.ConsumeView(ctx, "racedtwice123456"); !errors.Is(err, storagetypes.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if _, ok := fake.items["racedtwice123456"]; !ok {
		t.Error("a denied request must not delete the item")
	}
}

func TestDynamo_ConsumeView_ItemVanishedMidRace(t *testing.T) {
	store, fake := newTestDynamoStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "vanished12345678", []byte(`{}`), nil, ptrInt(5))
	fake.beforeUpdate = func() { delete(fake.items, "vanished12345678") }
	fake.condFailUpdate = true

	if _, err := store.ConsumeView(ctx, "vanished12345678"); !errors.Is(err, storagetypes.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// --- DeleteSecret ---

func TestDynamo_DeleteSecret(t *testing.T) {
	store, fake := newTestDynamoStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "deleteme12345678", []byte(`{}`), nil, nil)
	if err := store.DeleteSecret(ctx, "deleteme12345678"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, ok := fake.items["deleteme12345678"]; ok {
		t.Error("item should be gone after DeleteSecret")
	}
}
