package main

import (
	"context"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	echo "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nckslvrmn/whisper/internal/config"
	"github.com/nckslvrmn/whisper/internal/handlers"
	custommw "github.com/nckslvrmn/whisper/internal/middleware"
	"github.com/nckslvrmn/whisper/internal/storage"
)

type TemplateRegistry struct {
	templates map[string]*template.Template
}

func (t *TemplateRegistry) Render(w io.Writer, name string, data any, c echo.Context) error {
	if tmpl, ok := t.templates[name]; ok {
		return tmpl.Execute(w, data)
	}
	return echo.ErrNotFound
}

type TemplateData struct {
	ProjectName      string
	AdvancedFeatures bool
	MaxFileSizeMB    int
	MaxTextSizeMB    int
}

func getTemplateData() TemplateData {
	return TemplateData{
		ProjectName:      config.ProjectName,
		AdvancedFeatures: config.AdvancedFeatures,
		MaxFileSizeMB:    config.MaxFileSizeMB,
		MaxTextSizeMB:    config.MaxTextSizeMB,
	}
}

// runHealthcheck backs the container HEALTHCHECK. The scratch image has no
// shell or curl, so the binary probes itself.
func runHealthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://localhost:" + port + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck failed:", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck failed: HTTP", resp.StatusCode)
		return 1
	}
	return 0
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe a running server on $PORT and exit 0 when healthy")
	flag.Parse()
	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	e := echo.New()

	if err := config.LoadAppConfig(); err != nil {
		e.Logger.Fatal(err)
	}

	if err := storage.Initialize(); err != nil {
		e.Logger.Fatal(err)
	}

	compressedCache := custommw.NewCompressedFileCache("web/static")
	if err := compressedCache.PrecompressStaticFiles(); err != nil {
		e.Logger.Warnf("Failed to pre-compress static files: %v", err)
	} else {
		e.Logger.Info("Pre-compressed static files successfully")
	}

	templates := map[string]*template.Template{
		"index":  template.Must(template.ParseFiles("web/templates/layout.html", "web/templates/index.html")),
		"secret": template.Must(template.ParseFiles("web/templates/layout.html", "web/templates/secret.html")),
	}

	t := &TemplateRegistry{
		templates: templates,
	}

	e.Renderer = t

	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
		HSTSMaxAge:         31536000,
		ContentSecurityPolicy: "default-src 'self'; " +
			// 'wasm-unsafe-eval' is required for WebAssembly.instantiateStreaming().
			// It permits WASM bytecode compilation only — not arbitrary JS eval.
			"script-src 'self' 'wasm-unsafe-eval' https://cdnjs.cloudflare.com; " +
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " +
			"font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
			"img-src 'self' data:; " +
			"connect-src 'self' https://cdnjs.cloudflare.com; " +
			"worker-src 'self'; " +
			"frame-ancestors 'none'; " +
			"base-uri 'self'; " +
			"object-src 'none';",
		ReferrerPolicy: "strict-origin-when-cross-origin",
	}))

	// Caching headers for /static are set inside this middleware. It answers
	// compressed requests itself without calling next, so anything downstream
	// would miss them.
	e.Use(compressedCache.Middleware)
	e.Static("/static", "web/static")

	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
		// Static assets are pre-compressed, and every API body is ciphertext
		// or base64 ciphertext, which gzip cannot shrink.
		Skipper: func(c echo.Context) bool {
			path := c.Path()
			switch path {
			case "/encrypt", "/encrypt_file", "/decrypt", "/healthz":
				return true
			}
			return len(path) >= 7 && path[:7] == "/static"
		},
	}))
	e.Use(middleware.Recover())
	e.Use(middleware.RequestLogger())

	e.Use(middleware.ContextTimeoutWithConfig(middleware.ContextTimeoutConfig{
		Timeout: 30 * time.Second,
	}))

	e.Use(middleware.BodyLimit(fmt.Sprintf("%dM", config.MaxFileSizeMB)))

	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(100)))

	e.HideBanner = true
	e.HidePort = true

	e.GET("/", index)
	e.GET("/healthz", healthz)
	e.GET("/secret/:secret_id", secret)
	e.POST("/encrypt", handlers.EncryptString)
	e.POST("/encrypt_file", handlers.EncryptFile)
	e.POST("/decrypt", handlers.Decrypt)

	go func() {
		if err := e.Start(":" + config.Port); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	e.Logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}

	if err := storage.Close(); err != nil {
		e.Logger.Errorf("error closing storage: %v", err)
	}

	e.Logger.Info("Server shutdown complete")
}

func healthz(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func index(c echo.Context) error {
	return c.Render(http.StatusOK, "index", getTemplateData())
}

func secret(c echo.Context) error {
	return c.Render(http.StatusOK, "secret", getTemplateData())
}
