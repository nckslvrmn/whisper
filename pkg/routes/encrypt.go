package routes

import (
	"encoding/json"
	"io"
	"net/http"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/go_ots/pkg/simple_crypt"
	"github.com/nckslvrmn/go_ots/pkg/storage"
	"github.com/nckslvrmn/go_ots/pkg/utils"
)

func EncryptString(c echo.Context) error {
	var encryptData struct {
		Secret    string `json:"secret"`
		ViewCount string `json:"view_count"`
	}

	err := c.Bind(&encryptData)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}

	secret := simple_crypt.NewSecret()
	secret.ViewCount = utils.SanitizeViewCount(encryptData.ViewCount)
	secret.Data, err = secret.Encrypt([]byte(encryptData.Secret))
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}

	return storeAndReturn(c, secret)
}

func EncryptFile(c echo.Context) error {
	formFile, err := c.FormFile("file")
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}

	secret := simple_crypt.NewSecret()
	secret.ViewCount = 1
	secret.IsFile = true

	f, err := formFile.Open()
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}
	contents, err := io.ReadAll(f)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}
	encrypted, err := secret.Encrypt(contents)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}

	fileStore := storage.GetFileStore()
	if err := fileStore.StoreEncryptedFile(secret.SecretId, encrypted); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}

	js, _ := json.Marshal(map[string]string{
		"file_name": formFile.Filename,
		"file_type": c.FormValue("type"),
	})
	secret.Data, err = secret.Encrypt(js)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}

	return storeAndReturn(c, secret)
}

func storeAndReturn(c echo.Context, secret *simple_crypt.Secret) error {
	secretStore := storage.GetSecretStore()
	if err := secretStore.StoreSecret(secret); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}

	return c.JSON(http.StatusOK, map[string]string{"secret_id": secret.SecretId, "passphrase": secret.Passphrase})
}
