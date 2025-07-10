package gcp

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
)

// mockReadCloser implements io.ReadCloser for testing
type mockReadCloser struct {
	reader io.Reader
	err    error
}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.reader.Read(p)
}

func (m *mockReadCloser) Close() error {
	return nil
}

// mockWriter implements io.WriteCloser for testing
type mockWriter struct {
	writeErr error
	closeErr error
	written  []byte
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.written = append(m.written, p...)
	return len(p), nil
}

func (m *mockWriter) Close() error {
	return m.closeErr
}

// mockObjectHandle implements ObjectHandleInterface for testing
type mockObjectHandle struct {
	reader    *mockReadCloser
	writer    *mockWriter
	deleteErr error
}

func (m *mockObjectHandle) NewReader(ctx context.Context) (io.ReadCloser, error) {
	if m.reader == nil {
		return nil, storage.ErrObjectNotExist
	}
	return m.reader, nil
}

func (m *mockObjectHandle) NewWriter(ctx context.Context) io.WriteCloser {
	return m.writer
}

func (m *mockObjectHandle) Delete(ctx context.Context) error {
	return m.deleteErr
}

// mockBucketHandle implements BucketHandleInterface for testing
type mockBucketHandle struct {
	objects map[string]*mockObjectHandle
}

func (m *mockBucketHandle) Object(name string) ObjectHandleInterface {
	if obj, ok := m.objects[name]; ok {
		return obj
	}
	return &mockObjectHandle{
		reader: nil,
	}
}

func TestGCSStore_StoreEncryptedFile(t *testing.T) {
	tests := []struct {
		name     string
		secretID string
		data     []byte
		writeErr error
		closeErr error
		wantErr  bool
	}{
		{
			name:     "successful store",
			secretID: "test-id",
			data:     []byte("test data"),
			wantErr:  false,
		},
		{
			name:     "write error",
			secretID: "test-id",
			data:     []byte("test data"),
			writeErr: errors.New("write error"),
			wantErr:  true,
		},
		{
			name:     "close error",
			secretID: "test-id",
			data:     []byte("test data"),
			closeErr: errors.New("close error"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := &mockWriter{
				writeErr: tt.writeErr,
				closeErr: tt.closeErr,
			}

			bucket := &mockBucketHandle{
				objects: map[string]*mockObjectHandle{
					tt.secretID + ".enc": {
						writer: writer,
					},
				},
			}

			store := &GCSStore{
				bucket: bucket,
			}

			err := store.StoreEncryptedFile(tt.secretID, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("StoreEncryptedFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if string(writer.written) != string(tt.data) {
					t.Errorf("StoreEncryptedFile() written = %v, want %v", string(writer.written), string(tt.data))
				}
			}
		})
	}
}

func TestGCSStore_GetEncryptedFile(t *testing.T) {
	tests := []struct {
		name     string
		secretID string
		data     string
		readErr  error
		wantErr  bool
	}{
		{
			name:     "successful get",
			secretID: "test-id",
			data:     utils.B64E([]byte("test data")),
			wantErr:  false,
		},
		{
			name:     "read error",
			secretID: "test-id",
			readErr:  errors.New("read error"),
			wantErr:  true,
		},
		{
			name:     "object not found",
			secretID: "non-existent",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reader *mockReadCloser
			if tt.data != "" {
				reader = &mockReadCloser{
					reader: strings.NewReader(tt.data),
					err:    tt.readErr,
				}
			}

			bucket := &mockBucketHandle{
				objects: map[string]*mockObjectHandle{
					tt.secretID + ".enc": {
						reader: reader,
					},
				},
			}

			store := &GCSStore{
				bucket: bucket,
			}

			got, err := store.GetEncryptedFile(tt.secretID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetEncryptedFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(got) != tt.data {
				t.Errorf("GetEncryptedFile() = %v, want %v", string(got), tt.data)
			}
		})
	}
}

func TestGCSStore_DeleteEncryptedFile(t *testing.T) {
	tests := []struct {
		name      string
		secretID  string
		deleteErr error
		wantErr   bool
	}{
		{
			name:     "successful delete",
			secretID: "test-id",
			wantErr:  false,
		},
		{
			name:      "delete error",
			secretID:  "test-id",
			deleteErr: errors.New("delete error"),
			wantErr:   true,
		},
		{
			name:     "object not found",
			secretID: "non-existent",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket := &mockBucketHandle{
				objects: map[string]*mockObjectHandle{
					tt.secretID + ".enc": {
						deleteErr: tt.deleteErr,
					},
				},
			}

			store := &GCSStore{
				bucket: bucket,
			}

			err := store.DeleteEncryptedFile(tt.secretID)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteEncryptedFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
