package merror_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/wonksing/oauth-server/pkg/models/merror"
)

func TestHttpError(t *testing.T) {
	var err error

	err = merror.ErrorNoAllowedResource
	switch err := err.(type) {
	case *merror.OAuthError:
		data := err.ResponseData()
		fmt.Println("oautherror", data)
	default:
		data := make(map[string]interface{})
		data["error"] = http.StatusText(http.StatusBadRequest)
		data["error_description"] = err.Error()
		fmt.Println("default", data)
	}
}
