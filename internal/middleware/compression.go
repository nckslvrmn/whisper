package middleware

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/labstack/echo/v4"
)

// staticCacheControl makes browsers revalidate every static asset. The whole
// directory is app code that changes each release and shares one URL, so a
// freshness window would serve a stale main.js or crypto.js against a new
// server. Revalidation costs an empty 304 when the ETag still matches.
const staticCacheControl = "public, no-cache"

type CompressedFileCache struct {
	mu         sync.RWMutex
	brotli     map[string]bool
	gzip       map[string]bool
	etags      map[string]string
	baseDir    string
	absBaseDir string
}

func NewCompressedFileCache(baseDir string) *CompressedFileCache {
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		absBaseDir = baseDir
	}
	return &CompressedFileCache{
		brotli:     make(map[string]bool),
		gzip:       make(map[string]bool),
		etags:      make(map[string]string),
		baseDir:    baseDir,
		absBaseDir: absBaseDir,
	}
}

func (c *CompressedFileCache) PrecompressStaticFiles() error {
	return filepath.Walk(c.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		if strings.HasSuffix(path, ".br") || strings.HasSuffix(path, ".gz") {
			return nil
		}

		relPath := strings.TrimPrefix(path, c.baseDir)
		etag, err := contentETag(path)
		if err != nil {
			return err
		}

		// Compressing a file smaller than one packet costs more than it saves.
		var hasBr, hasGz bool
		if info.Size() >= 512 {
			hasBr = !isStale(path+".br", info)
			hasGz = !isStale(path+".gz", info)

			if !hasBr {
				if err := compressBrotli(path); err == nil {
					hasBr = true
				}
			}

			if !hasGz {
				if err := compressGzip(path); err == nil {
					hasGz = true
				}
			}
		}

		c.mu.Lock()
		c.brotli[relPath] = hasBr
		c.gzip[relPath] = hasGz
		c.etags[relPath] = etag
		c.mu.Unlock()

		return nil
	})
}

// contentETag hashes the file rather than using its mtime, so a rebuild that
// leaves the bytes identical still revalidates to a 304.
func contentETag(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil))[:16], nil
}

func (c *CompressedFileCache) Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		if !strings.HasPrefix(ctx.Path(), "/static") {
			return next(ctx)
		}

		acceptEncoding := ctx.Request().Header.Get("Accept-Encoding")
		relPath := strings.TrimPrefix(ctx.Request().URL.Path, "/static")
		relPath = filepath.Clean(relPath)

		c.mu.RLock()
		hasBr := c.brotli[relPath]
		hasGz := c.gzip[relPath]
		etag := c.etags[relPath]
		c.mu.RUnlock()

		// Every representation of the URL carries these, so a shared cache can
		// never key one encoding's body to a request that asked for another.
		header := ctx.Response().Header()
		header.Set("Vary", "Accept-Encoding")
		header.Set("Cache-Control", staticCacheControl)

		if hasBr && strings.Contains(acceptEncoding, "br") {
			absPath, err := filepath.Abs(filepath.Join(c.baseDir, relPath+".br"))
			if err != nil || !strings.HasPrefix(absPath, c.absBaseDir) {
				return next(ctx)
			}
			header.Set("Content-Encoding", "br")
			header.Set("Content-Type", getContentType(relPath))
			setETag(header, etag, "br")
			return ctx.File(absPath)
		}

		if hasGz && strings.Contains(acceptEncoding, "gzip") {
			absPath, err := filepath.Abs(filepath.Join(c.baseDir, relPath+".gz"))
			if err != nil || !strings.HasPrefix(absPath, c.absBaseDir) {
				return next(ctx)
			}
			header.Set("Content-Encoding", "gzip")
			header.Set("Content-Type", getContentType(relPath))
			setETag(header, etag, "gzip")
			return ctx.File(absPath)
		}

		setETag(header, etag, "")
		return next(ctx)
	}
}

// setETag tags each encoding separately, since a compressed body and a plain
// one are different representations of the same URL. http.ServeContent reads
// this header back to answer If-None-Match, so setting it here is what turns a
// revalidation into a 304.
func setETag(header http.Header, etag, encoding string) {
	if etag == "" {
		return
	}
	if encoding != "" {
		etag += "-" + encoding
	}
	header.Set("ETag", `"`+etag+`"`)
}

// isStale reports whether a compressed copy is missing or older than its
// source. Without the age check, a leftover .br from an earlier build keeps
// being served after the source is regenerated, which desyncs the WASM glue
// from the module it loads.
func isStale(compressedPath string, source os.FileInfo) bool {
	info, err := os.Stat(compressedPath)
	if err != nil {
		return true
	}
	return info.ModTime().Before(source.ModTime())
}

func compressBrotli(srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(srcPath + ".br")
	if err != nil {
		return err
	}
	defer dst.Close()

	w := brotli.NewWriterLevel(dst, brotli.BestCompression)
	defer w.Close()

	_, err = io.Copy(w, src)
	return err
}

func compressGzip(srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(srcPath + ".gz")
	if err != nil {
		return err
	}
	defer dst.Close()

	w, err := gzip.NewWriterLevel(dst, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = io.Copy(w, src)
	return err
}

func getContentType(path string) string {
	// Hardcode types that may be absent from minimal OS MIME databases (e.g. Alpine).
	switch filepath.Ext(path) {
	case ".wasm":
		return "application/wasm"
	case ".js", ".mjs":
		return "application/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	}
	contentType := mime.TypeByExtension(filepath.Ext(path))
	if contentType == "" {
		return "application/octet-stream"
	}
	return contentType
}
