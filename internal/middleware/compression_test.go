package middleware_test

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/nckslvrmn/whisper/internal/middleware"
)

// writeFile creates a file with at least 512 bytes of content so PrecompressStaticFiles
// considers it worth compressing.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeFile %s: %v", name, err)
	}
	return path
}

func largeContent() string {
	return strings.Repeat("hello world test content for compression ", 30)
}

// --- getContentType (tested via middleware responses) ---

func TestGetContentType_WASM(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "test.wasm", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	e := echo.New()
	handler := cache.Middleware(func(ctx echo.Context) error {
		return ctx.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/static/test.wasm", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/static/test.wasm")

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/wasm" {
		t.Errorf("Content-Type = %q, want application/wasm", ct)
	}
}

func TestGetContentType_JS(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	e := echo.New()
	handler := cache.Middleware(func(ctx echo.Context) error {
		return ctx.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/static/app.js")

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/javascript") {
		t.Errorf("Content-Type = %q, want application/javascript", ct)
	}
}

func TestGetContentType_CSS(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "style.css", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	e := echo.New()
	handler := cache.Middleware(func(ctx echo.Context) error {
		return ctx.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/static/style.css", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/static/style.css")

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/css") {
		t.Errorf("Content-Type = %q, want text/css", ct)
	}
}

// --- PrecompressStaticFiles ---

func TestPrecompressStaticFiles_CreatesGZAndBR(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.js", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	if err := cache.PrecompressStaticFiles(); err != nil {
		t.Fatalf("PrecompressStaticFiles: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "bundle.js.gz")); os.IsNotExist(err) {
		t.Error("bundle.js.gz not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "bundle.js.br")); os.IsNotExist(err) {
		t.Error("bundle.js.br not created")
	}
}

func TestPrecompressStaticFiles_SkipsSmallFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "tiny.js", "small")

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	if _, err := os.Stat(filepath.Join(dir, "tiny.js.gz")); !os.IsNotExist(err) {
		t.Error("tiny.js.gz should not be created for files < 512 bytes")
	}
}

func TestPrecompressStaticFiles_SkipsAlreadyCompressed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "already.js.gz", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	// Should not error when encountering .gz or .br files
	if err := cache.PrecompressStaticFiles(); err != nil {
		t.Fatalf("PrecompressStaticFiles: %v", err)
	}
}

func TestPrecompressStaticFiles_DoesNotRecompressExisting(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "page.js", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	// Record mtime of .gz
	info1, _ := os.Stat(filepath.Join(dir, "page.js.gz"))

	// Run again
	cache.PrecompressStaticFiles()

	info2, _ := os.Stat(filepath.Join(dir, "page.js.gz"))
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Error("PrecompressStaticFiles recompressed an already-compressed file")
	}
}

// --- Middleware: routing ---

func TestMiddleware_NonStaticPath_PassesThrough(t *testing.T) {
	dir := t.TempDir()
	cache := middleware.NewCompressedFileCache(dir)

	e := echo.New()
	called := false
	handler := cache.Middleware(func(ctx echo.Context) error {
		called = true
		return ctx.String(http.StatusOK, "next")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/api/secrets")

	handler(ctx)
	if !called {
		t.Error("non-/static path should pass through to next handler")
	}
}

func TestMiddleware_NoAcceptEncoding_PassesThrough(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.js", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	e := echo.New()
	called := false
	handler := cache.Middleware(func(ctx echo.Context) error {
		called = true
		return ctx.String(http.StatusOK, "next")
	})

	req := httptest.NewRequest(http.MethodGet, "/static/main.js", nil)
	// No Accept-Encoding header
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/static/main.js")

	handler(ctx)
	if !called {
		t.Error("request without Accept-Encoding should pass through to next handler")
	}
}

func TestMiddleware_GzipAccepted_SetsHeaders(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.js", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	e := echo.New()
	handler := cache.Middleware(func(ctx echo.Context) error {
		return ctx.String(http.StatusOK, "next")
	})

	req := httptest.NewRequest(http.MethodGet, "/static/main.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/static/main.js")

	handler(ctx)

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", rec.Header().Get("Content-Encoding"))
	}
	if rec.Header().Get("Vary") != "Accept-Encoding" {
		t.Errorf("Vary = %q, want Accept-Encoding", rec.Header().Get("Vary"))
	}
}

func TestMiddleware_GzipContent_IsValidGzip(t *testing.T) {
	dir := t.TempDir()
	content := largeContent()
	writeFile(t, dir, "script.js", content)

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	e := echo.New()
	handler := cache.Middleware(func(ctx echo.Context) error {
		return ctx.String(http.StatusOK, "next")
	})

	req := httptest.NewRequest(http.MethodGet, "/static/script.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/static/script.js")

	if err := handler(ctx); err != nil {
		t.Fatalf("handler: %v", err)
	}

	gr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("response is not valid gzip: %v", err)
	}
	defer gr.Close()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(decompressed) != content {
		t.Error("decompressed content does not match original")
	}
}

func TestMiddleware_BrotliAccepted_SetsHeaders(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.css", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	e := echo.New()
	handler := cache.Middleware(func(ctx echo.Context) error {
		return ctx.String(http.StatusOK, "next")
	})

	req := httptest.NewRequest(http.MethodGet, "/static/bundle.css", nil)
	req.Header.Set("Accept-Encoding", "br")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/static/bundle.css")

	handler(ctx)

	if rec.Header().Get("Content-Encoding") != "br" {
		t.Errorf("Content-Encoding = %q, want br", rec.Header().Get("Content-Encoding"))
	}
}

// --- Path traversal in middleware ---

func TestMiddleware_PathTraversal_PassesThrough(t *testing.T) {
	dir := t.TempDir()
	cache := middleware.NewCompressedFileCache(dir)

	e := echo.New()
	called := false
	handler := cache.Middleware(func(ctx echo.Context) error {
		called = true
		return ctx.String(http.StatusOK, "next")
	})

	req := httptest.NewRequest(http.MethodGet, "/static/../etc/passwd", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetPath("/static/../etc/passwd")

	handler(ctx)
	// Should pass through to next (no compressed version of /etc/passwd)
	if !called {
		// It's also acceptable to return an error — just must not serve arbitrary files.
		if rec.Code == http.StatusOK && !strings.Contains(rec.Body.String(), "next") {
			t.Error("path traversal should not serve arbitrary files")
		}
	}
}
