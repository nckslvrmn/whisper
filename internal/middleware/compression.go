package middleware

import (
	"compress/gzip"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/labstack/echo/v4"
)

type CompressedFileCache struct {
	mu         sync.RWMutex
	brotli     map[string]bool
	gzip       map[string]bool
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

		if info.Size() < 512 {
			return nil
		}

		relPath := strings.TrimPrefix(path, c.baseDir)

		hasBr := fileExists(path + ".br")
		hasGz := fileExists(path + ".gz")

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

		c.mu.Lock()
		c.brotli[relPath] = hasBr
		c.gzip[relPath] = hasGz
		c.mu.Unlock()

		return nil
	})
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
		c.mu.RUnlock()

		if hasBr && strings.Contains(acceptEncoding, "br") {
			absPath, err := filepath.Abs(filepath.Join(c.baseDir, relPath+".br"))
			if err != nil || !strings.HasPrefix(absPath, c.absBaseDir) {
				return next(ctx)
			}
			ctx.Response().Header().Set("Content-Encoding", "br")
			ctx.Response().Header().Set("Content-Type", getContentType(relPath))
			ctx.Response().Header().Set("Vary", "Accept-Encoding")
			return ctx.File(absPath)
		}

		if hasGz && strings.Contains(acceptEncoding, "gzip") {
			absPath, err := filepath.Abs(filepath.Join(c.baseDir, relPath+".gz"))
			if err != nil || !strings.HasPrefix(absPath, c.absBaseDir) {
				return next(ctx)
			}
			ctx.Response().Header().Set("Content-Encoding", "gzip")
			ctx.Response().Header().Set("Content-Type", getContentType(relPath))
			ctx.Response().Header().Set("Vary", "Accept-Encoding")
			return ctx.File(absPath)
		}

		return next(ctx)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
