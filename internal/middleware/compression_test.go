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
	"time"

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

func TestPrecompressStaticFiles_RecompressesStaleCopies(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "crypto.js", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	before := map[string]time.Time{}
	for _, name := range []string{"crypto.js.gz", "crypto.js.br"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		before[name] = info.ModTime()
	}

	// A rebuild rewrites the source and leaves the old compressed copies in
	// place. Serving those would hand out glue that no longer matches the
	// module it loads.
	rebuilt := largeContent() + "// regenerated by a later build\n"
	if err := os.WriteFile(path, []byte(rebuilt), 0644); err != nil {
		t.Fatalf("rewrite source: %v", err)
	}
	touched := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, touched, touched); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	cache.PrecompressStaticFiles()

	for name, was := range before {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.ModTime().Equal(was) {
			t.Errorf("%s was not regenerated after its source changed", name)
		}
	}

	gz, err := os.Open(filepath.Join(dir, "crypto.js.gz"))
	if err != nil {
		t.Fatalf("open gz: %v", err)
	}
	defer gz.Close()
	reader, err := gzip.NewReader(gz)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gz: %v", err)
	}
	if string(got) != rebuilt {
		t.Error("regenerated .gz does not hold the current source")
	}
}

// --- Middleware: caching headers ---

func TestMiddleware_CachingHeadersOnEveryEncoding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	cases := map[string]string{"br": "br", "gzip": "gzip", "": ""}
	tags := map[string]string{}

	for encoding, wantEncoding := range cases {
		rec := serveStatic(t, cache, dir, "/static/app.js", encoding)

		if got := rec.Header().Get("Cache-Control"); got != "public, no-cache" {
			t.Errorf("%q: Cache-Control = %q", encoding, got)
		}
		if got := rec.Header().Get("Vary"); got != "Accept-Encoding" {
			t.Errorf("%q: Vary = %q", encoding, got)
		}
		if got := rec.Header().Get("Content-Encoding"); got != wantEncoding {
			t.Errorf("%q: Content-Encoding = %q, want %q", encoding, got, wantEncoding)
		}
		etag := rec.Header().Get("ETag")
		if etag == "" {
			t.Errorf("%q: missing ETag", encoding)
		}
		tags[encoding] = etag
	}

	if tags["br"] == tags[""] || tags["gzip"] == tags[""] || tags["br"] == tags["gzip"] {
		t.Errorf("each encoding needs its own ETag, got %v", tags)
	}
}

func TestMiddleware_ETagTracksContentNotMtime(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "app.js", largeContent())

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()
	before := serveStatic(t, cache, dir, "/static/app.js", "").Header().Get("ETag")

	// A rebuild that leaves the bytes alone must not invalidate caches.
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	cache = middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()
	if got := serveStatic(t, cache, dir, "/static/app.js", "").Header().Get("ETag"); got != before {
		t.Errorf("ETag changed on an mtime-only rebuild: %q then %q", before, got)
	}

	// Changed bytes must invalidate.
	if err := os.WriteFile(path, []byte(largeContent()+"// new release\n"), 0644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	cache = middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()
	if got := serveStatic(t, cache, dir, "/static/app.js", ""); got.Header().Get("ETag") == before {
		t.Error("ETag did not change after the content changed")
	}
}

func TestMiddleware_SmallFilesStillGetHeaders(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "tiny.js", "let a = 1;\n")

	cache := middleware.NewCompressedFileCache(dir)
	cache.PrecompressStaticFiles()

	rec := serveStatic(t, cache, dir, "/static/tiny.js", "br")
	if rec.Header().Get("Cache-Control") == "" || rec.Header().Get("ETag") == "" {
		t.Error("a file too small to compress still needs caching headers")
	}
	if rec.Header().Get("Content-Encoding") != "" {
		t.Error("a file too small to compress must not claim an encoding")
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

// serveStatic runs one /static request through the middleware chain and
// returns the recorded response.
func serveStatic(t *testing.T, cache *middleware.CompressedFileCache, dir, target, acceptEncoding string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	e.Use(cache.Middleware)
	e.Static("/static", dir)

	req := httptest.NewRequest(http.MethodGet, target, nil)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}
