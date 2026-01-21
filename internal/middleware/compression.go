package middleware

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/labstack/echo/v4"
)

type CompressedFileCache struct {
	mu      sync.RWMutex
	brotli  map[string]bool
	gzip    map[string]bool
	baseDir string
}

func NewCompressedFileCache(baseDir string) *CompressedFileCache {
	return &CompressedFileCache{
		brotli:  make(map[string]bool),
		gzip:    make(map[string]bool),
		baseDir: baseDir,
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

		c.mu.RLock()
		hasBr := c.brotli[relPath]
		hasGz := c.gzip[relPath]
		c.mu.RUnlock()

		if hasBr && strings.Contains(acceptEncoding, "br") {
			brPath := filepath.Join(c.baseDir, relPath+".br")
			ctx.Response().Header().Set("Content-Encoding", "br")
			ctx.Response().Header().Set("Content-Type", getContentType(relPath))
			ctx.Response().Header().Set("Vary", "Accept-Encoding")
			return ctx.File(brPath)
		}

		if hasGz && strings.Contains(acceptEncoding, "gzip") {
			gzPath := filepath.Join(c.baseDir, relPath+".gz")
			ctx.Response().Header().Set("Content-Encoding", "gzip")
			ctx.Response().Header().Set("Content-Type", getContentType(relPath))
			ctx.Response().Header().Set("Vary", "Accept-Encoding")
			return ctx.File(gzPath)
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
	switch {
	case strings.HasSuffix(path, ".wasm"):
		return "application/wasm"
	case strings.HasSuffix(path, ".js"):
		return "application/javascript"
	case strings.HasSuffix(path, ".css"):
		return "text/css"
	case strings.HasSuffix(path, ".json"):
		return "application/json"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(path, ".woff"), strings.HasSuffix(path, ".woff2"):
		return "font/woff2"
	default:
		return "application/octet-stream"
	}
}
