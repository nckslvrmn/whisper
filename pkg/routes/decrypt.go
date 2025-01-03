package routes

import (
	"encoding/json"
	"fmt"
	"net/http"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/go_ots/pkg/ots_dynamo"
	"github.com/nckslvrmn/go_ots/pkg/ots_s3"
	"github.com/nckslvrmn/go_ots/pkg/utils"
)

var decryptData struct {
	SecretId   string `json:"secret_id"`
	Passphrase string `json:"passphrase"`
}

type decryptedFile struct {
	FileName string `json:"file_name"`
	FileType string `json:"file_type"`
}

func Decrypt(c echo.Context) error {
	if err := c.Bind(&decryptData); err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusNotFound)
	}

	secret, err := ots_dynamo.GetSecret(decryptData.SecretId)
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusNotFound)
	}

	secret.Passphrase = decryptData.Passphrase
	decrypted, err := secret.Decrypt()
	if err != nil {
		c.Logger().Error(err)
		return c.NoContent(http.StatusNotFound)
	}

	var decryptedJson decryptedFile
	if secret.IsFile {
		json.Unmarshal(decrypted, &decryptedJson)
		fileData, err := ots_s3.GetEncryptedFile(secret.SecretId)
		if err != nil {
			c.Logger().Error(err)
			return c.NoContent(http.StatusNotFound)
		}
		secret.Data, err = utils.B64D(string(fileData))
		if err != nil {
			c.Logger().Error(err)
			return c.NoContent(http.StatusNotFound)
		}
		decrypted, err = secret.Decrypt()
		if err != nil {
			c.Logger().Error(err)
			return c.NoContent(http.StatusNotFound)
		}
		ots_s3.DeleteEncryptedFile(secret.SecretId)
	}

	secret.ViewCount--
	if secret.ViewCount <= 0 {
		ots_dynamo.DeleteSecret(secret.SecretId)
	} else {
		ots_dynamo.UpdateSecret(secret)
	}

	if secret.IsFile {
		c.Response().Header().Set(echo.HeaderContentDisposition, fmt.Sprintf("attachment; filename=%s", decryptedJson.FileName))
		return c.Blob(http.StatusOK, decryptedJson.FileType, decrypted)
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": string(decrypted),
	})
}
