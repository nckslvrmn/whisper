package main

import (
	"html/template"
	"io"
	"net/http"

	echo "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nckslvrmn/secure_secret_share/pkg/routes"
	"github.com/nckslvrmn/secure_secret_share/pkg/storage"
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
	templates["index"] = template.Must(template.ParseFiles("views/layout.html", "views/index.html"))
	templates["secret"] = template.Must(template.ParseFiles("views/layout.html", "views/secret.html"))

	e.Static("/static", "static")
	e.Renderer = t
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.HideBanner = true
	e.HidePort = true

	e.GET("/", index)
	e.GET("/secret/:secret_id", secret)
	e.POST("/encrypt", routes.EncryptString)
	e.POST("/encrypt_file", routes.EncryptFile)
	e.POST("/decrypt", routes.Decrypt)

	e.Logger.Fatal(e.Start(":8081"))
}

func index(c echo.Context) error {
	return c.Render(http.StatusOK, "index", nil)
}

func secret(c echo.Context) error {
	return c.Render(http.StatusOK, "secret", nil)
}
