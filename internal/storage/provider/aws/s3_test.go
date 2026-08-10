package aws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/nckslvrmn/whisper/internal/config"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
	"github.com/nckslvrmn/whisper/pkg/utils"
)

type fakeS3 struct {
	objects map[string][]byte
	failGet error
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string][]byte{}}
}

func (f *fakeS3) PutObject(ctx context.Context, params *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	body, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}
	f.objects[*params.Key] = body
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(ctx context.Context, params *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if f.failGet != nil {
		return nil, f.failGet
	}
	body, ok := f.objects[*params.Key]
	if !ok {
		return nil, &s3types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func (f *fakeS3) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	delete(f.objects, *params.Key)
	return &s3.DeleteObjectOutput{}, nil
}

// The multipart path only triggers above the uploader's part size, which test
// payloads never reach.
func (f *fakeS3) UploadPart(context.Context, *s3.UploadPartInput, ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	return nil, errors.New("unexpected multipart upload")
}

func (f *fakeS3) CreateMultipartUpload(context.Context, *s3.CreateMultipartUploadInput, ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	return nil, errors.New("unexpected multipart upload")
}

func (f *fakeS3) CompleteMultipartUpload(context.Context, *s3.CompleteMultipartUploadInput, ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	return nil, errors.New("unexpected multipart upload")
}

func (f *fakeS3) AbortMultipartUpload(context.Context, *s3.AbortMultipartUploadInput, ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	return nil, errors.New("unexpected multipart upload")
}

func newTestS3Store(t *testing.T) (*S3Store, *fakeS3) {
	t.Helper()
	config.S3Bucket = "test-bucket"
	fake := newFakeS3()
	return &S3Store{client: fake}, fake
}

func readAll(t *testing.T, store *S3Store, id string) ([]byte, error) {
	t.Helper()
	rc, err := store.GetEncryptedFile(context.Background(), id)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func TestS3_StoreAndGet(t *testing.T) {
	store, fake := newTestS3Store(t)

	data := bytes.Repeat([]byte{0x00, 0xFF, 0xA5}, 400)
	if err := store.StoreEncryptedFile(context.Background(), "abcdefghijklmnop", bytes.NewReader(data)); err != nil {
		t.Fatalf("StoreEncryptedFile: %v", err)
	}

	if !bytes.Equal(fake.objects["abcdefghijklmnop.enc"], data) {
		t.Error("object bytes at rest must be the raw ciphertext")
	}

	got, err := readAll(t, store, "abcdefghijklmnop")
	if err != nil {
		t.Fatalf("GetEncryptedFile: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("round-trip mismatch")
	}
}

func TestS3_StoreStreamsUnknownLength(t *testing.T) {
	store, fake := newTestS3Store(t)

	data := bytes.Repeat([]byte{0x42}, 100)
	// A bare Reader has no length and no Seek, which is what a streamed
	// multipart part looks like.
	body := io.MultiReader(bytes.NewReader(data))
	if err := store.StoreEncryptedFile(context.Background(), "streamed12345678", body); err != nil {
		t.Fatalf("StoreEncryptedFile: %v", err)
	}
	if !bytes.Equal(fake.objects["streamed12345678.enc"], data) {
		t.Error("streamed upload stored the wrong bytes")
	}
}

func TestS3_Get_LegacyBase64Object(t *testing.T) {
	store, fake := newTestS3Store(t)

	want := bytes.Repeat([]byte{0x01, 0x02, 0xFD}, 400)
	fake.objects["legacyfile123456.enc"] = []byte(utils.B64E(want))

	got, err := readAll(t, store, "legacyfile123456")
	if err != nil {
		t.Fatalf("GetEncryptedFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Error("legacy base64 object did not decode to the original ciphertext")
	}
}

func TestS3_Get_NotFound(t *testing.T) {
	store, _ := newTestS3Store(t)

	if _, err := readAll(t, store, "missing123456789"); !errors.Is(err, storagetypes.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestS3_Get_OtherErrorIsWrapped(t *testing.T) {
	store, fake := newTestS3Store(t)
	fake.failGet = errors.New("throttled")

	_, err := readAll(t, store, "abcdefghijklmnop")
	if err == nil || errors.Is(err, storagetypes.ErrNotFound) {
		t.Fatalf("err = %v, want a wrapped transport error", err)
	}
}

func TestS3_Delete(t *testing.T) {
	store, fake := newTestS3Store(t)
	ctx := context.Background()

	store.StoreEncryptedFile(ctx, "deleteme12345678", bytes.NewReader([]byte{1, 2, 3}))
	if err := store.DeleteEncryptedFile(ctx, "deleteme12345678"); err != nil {
		t.Fatalf("DeleteEncryptedFile: %v", err)
	}
	if _, ok := fake.objects["deleteme12345678.enc"]; ok {
		t.Error("object should be gone after delete")
	}
}
