package main

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	echo "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nckslvrmn/whisper/internal/config"
	"github.com/nckslvrmn/whisper/internal/handlers"
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
	ProjectName string
}

func getTemplateData() TemplateData {
	return TemplateData{
		ProjectName: config.ProjectName,
	}
}

func main() {
	e := echo.New()

	if err := config.LoadAppConfig(); err != nil {
		e.Logger.Fatal(err)
	}

	if err := storage.Initialize(); err != nil {
		e.Logger.Fatal(err)
	}

	var wg sync.WaitGroup
	templates := make(map[string]*template.Template)
	var mu sync.Mutex

	templateList := map[string][]string{
		"index":  {"web/templates/layout.html", "web/templates/index.html"},
		"secret": {"web/templates/layout.html", "web/templates/secret.html"},
	}

	for name, files := range templateList {
		wg.Add(1)
		go func(n string, f []string) {
			defer wg.Done()
			tmpl := template.Must(template.ParseFiles(f...))
			mu.Lock()
			templates[n] = tmpl
			mu.Unlock()
		}(name, files)
	}
	wg.Wait()

	t := &TemplateRegistry{
		templates: templates,
	}

	e.Static("/static", "web/static")
	e.Renderer = t

	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: 30 * time.Second,
	}))

	e.Use(middleware.BodyLimit("10M"))

	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(100)))

	e.HideBanner = true
	e.HidePort = true

	e.GET("/", index)
	e.GET("/secret/:secret_id", secret)
	e.POST("/encrypt", handlers.EncryptString)
	e.POST("/encrypt_file", handlers.EncryptFile)
	e.POST("/decrypt", handlers.Decrypt)

	go func() {
		if err := e.Start(":8081"); err != nil && err != http.ErrServerClosed {
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

	e.Logger.Info("Server shutdown complete")
}

func index(c echo.Context) error {
	return c.Render(http.StatusOK, "index", getTemplateData())
}

func secret(c echo.Context) error {
	return c.Render(http.StatusOK, "secret", getTemplateData())
}
