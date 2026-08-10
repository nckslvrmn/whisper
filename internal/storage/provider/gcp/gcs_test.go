package gcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"cloud.google.com/go/storage"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
	"github.com/nckslvrmn/whisper/pkg/utils"
)

type fakeBucket struct {
	objects map[string][]byte
	failGet error
}

func (b *fakeBucket) Object(name string) ObjectHandleInterface {
	return &fakeObject{bucket: b, name: name}
}

type fakeObject struct {
	bucket *fakeBucket
	name   string
}

func (o *fakeObject) NewReader(ctx context.Context) (io.ReadCloser, error) {
	if o.bucket.failGet != nil {
		return nil, o.bucket.failGet
	}
	data, ok := o.bucket.objects[o.name]
	if !ok {
		return nil, storage.ErrObjectNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (o *fakeObject) NewWriter(ctx context.Context) io.WriteCloser {
	return &fakeWriter{object: o}
}

func (o *fakeObject) Delete(ctx context.Context) error {
	if _, ok := o.bucket.objects[o.name]; !ok {
		return storage.ErrObjectNotExist
	}
	delete(o.bucket.objects, o.name)
	return nil
}

type fakeWriter struct {
	object *fakeObject
	buf    bytes.Buffer
}

func (w *fakeWriter) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

func (w *fakeWriter) Close() error {
	w.object.bucket.objects[w.object.name] = w.buf.Bytes()
	return nil
}

func newTestGCSStore(t *testing.T) (*GCSStore, *fakeBucket) {
	t.Helper()
	bucket := &fakeBucket{objects: map[string][]byte{}}
	return &GCSStore{bucket: bucket}, bucket
}

func readAll(t *testing.T, store *GCSStore, id string) ([]byte, error) {
	t.Helper()
	rc, err := store.GetEncryptedFile(context.Background(), id)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func TestGCS_StoreAndGet(t *testing.T) {
	store, bucket := newTestGCSStore(t)

	data := bytes.Repeat([]byte{0x00, 0xFF, 0x5A}, 400)
	if err := store.StoreEncryptedFile(context.Background(), "abcdefghijklmnop", bytes.NewReader(data)); err != nil {
		t.Fatalf("StoreEncryptedFile: %v", err)
	}

	if !bytes.Equal(bucket.objects["abcdefghijklmnop.enc"], data) {
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

func TestGCS_Get_LegacyBase64Object(t *testing.T) {
	store, bucket := newTestGCSStore(t)

	want := bytes.Repeat([]byte{0x09, 0x08, 0xF7}, 400)
	bucket.objects["legacyfile123456.enc"] = []byte(utils.B64E(want))

	got, err := readAll(t, store, "legacyfile123456")
	if err != nil {
		t.Fatalf("GetEncryptedFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Error("legacy base64 object did not decode to the original ciphertext")
	}
}

func TestGCS_Get_NotFound(t *testing.T) {
	store, _ := newTestGCSStore(t)

	if _, err := readAll(t, store, "missing123456789"); !errors.Is(err, storagetypes.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestGCS_Get_OtherErrorIsWrapped(t *testing.T) {
	store, bucket := newTestGCSStore(t)
	bucket.failGet = errors.New("permission denied")

	_, err := readAll(t, store, "abcdefghijklmnop")
	if err == nil || errors.Is(err, storagetypes.ErrNotFound) {
		t.Fatalf("err = %v, want a wrapped transport error", err)
	}
}

func TestGCS_Delete(t *testing.T) {
	store, bucket := newTestGCSStore(t)
	ctx := context.Background()

	store.StoreEncryptedFile(ctx, "deleteme12345678", bytes.NewReader([]byte{1, 2, 3}))
	if err := store.DeleteEncryptedFile(ctx, "deleteme12345678"); err != nil {
		t.Fatalf("DeleteEncryptedFile: %v", err)
	}
	if _, ok := bucket.objects["deleteme12345678.enc"]; ok {
		t.Error("object should be gone after delete")
	}
}

func TestGCS_Delete_MissingObjectIsNotAnError(t *testing.T) {
	store, _ := newTestGCSStore(t)

	if err := store.DeleteEncryptedFile(context.Background(), "missing123456789"); err != nil {
		t.Errorf("unexpected error deleting a missing object: %v", err)
	}
}
