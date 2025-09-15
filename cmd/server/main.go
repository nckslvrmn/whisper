package main

import (
	"html/template"
	"io"
	"net/http"

	echo "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nckslvrmn/secure_secret_share/internal/handlers"
	"github.com/nckslvrmn/secure_secret_share/internal/storage"
	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
)

type TemplateRegistry struct {
	templates map[string]*template.Template
}

func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates[name].Execute(w, data)
}

func main() {
	e := echo.New()
	err := utils.LoadEnv()
	if err != nil {
		e.Logger.Fatal(err)
	}

	if err := storage.Initialize(); err != nil {
		e.Logger.Fatal(err)
	}

	templates := make(map[string]*template.Template)
	t := &TemplateRegistry{
		templates: templates,
	}
	templates["index"] = template.Must(template.ParseFiles("web/templates/layout.html", "web/templates/index.html"))
	templates["secret"] = template.Must(template.ParseFiles("web/templates/layout.html", "web/templates/secret.html"))

	// Serve static files with compression support
	e.Static("/static", "web/static")
	e.Renderer = t
	
	// Enable gzip compression middleware
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.HideBanner = true
	e.HidePort = true

	e.GET("/", index)
	e.GET("/secret/:secret_id", secret)
	e.POST("/encrypt", handlers.EncryptString)
	e.POST("/encrypt_file", handlers.EncryptFile)
	e.POST("/decrypt", handlers.Decrypt)

	e.Logger.Fatal(e.Start(":8081"))
}

func index(c echo.Context) error {
	return c.Render(http.StatusOK, "index", nil)
}

func secret(c echo.Context) error {
	return c.Render(http.StatusOK, "secret", nil)
}
