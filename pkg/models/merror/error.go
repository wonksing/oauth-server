package merror

import (
	"encoding/json"
	"net/http"
)

type Error interface {
	// ReplaceError(err error) (string, string)
	error
}
type OAuthError struct {
	ErrMsg      string
	ErrCode     string
	Status      int
	Description string
}

func NewOAuthError(errCode, errMsg string, status int, description string) Error {
	return &OAuthError{
		ErrMsg:      errMsg,
		ErrCode:     errCode,
		Status:      status,
		Description: description,
	}
}

func (o *OAuthError) Error() string {
	return "(" + o.ErrCode + ")" + o.ErrMsg
}

func (o *OAuthError) ResponseData() map[string]interface{} {
	data := make(map[string]interface{})
	data["error"] = http.StatusText(o.Status)
	data["error_description"] = o.Description
	return data
}

var (
	// resource
	ErrorPageNotFound = NewOAuthError("1001", http.StatusText(http.StatusNotFound), http.StatusNotFound, http.StatusText(http.StatusNotFound)).(*OAuthError)

	// user auth
	ErrorUserIDNotFound  = NewOAuthError("2001", "사용자 아이디가 없습니다", http.StatusBadRequest, http.StatusText(http.StatusBadRequest)).(*OAuthError)
	ErrorUserNeedToAllow = NewOAuthError("2002", "사용자의 권한 허용이 필요합니다", http.StatusBadRequest, http.StatusText(http.StatusBadRequest)).(*OAuthError)
	ErrorUserDidNotAllow = NewOAuthError("2003", "사용자가 권한 사용을 거절하였습니다", http.StatusBadRequest, http.StatusText(http.StatusBadRequest)).(*OAuthError)

	// client validation
	ErrorNotAllowedRequestedScope = NewOAuthError("3001", "requested scope is not allowed", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)).(*OAuthError)
	ErrorNoAllowedResource        = NewOAuthError("3002", "no authorized resources", http.StatusBadRequest, http.StatusText(http.StatusBadRequest)).(*OAuthError)
	ErrorNoResourceToAccess       = NewOAuthError("3003", "no resource to access", http.StatusBadRequest, http.StatusText(http.StatusBadRequest)).(*OAuthError)
	ErrorNoClientID               = NewOAuthError("3004", "cannot find client id", http.StatusBadRequest, http.StatusText(http.StatusBadRequest)).(*OAuthError)
	ErrorNoRedirectURI            = NewOAuthError("3005", "cannot find redirect uri", http.StatusBadRequest, http.StatusText(http.StatusBadRequest)).(*OAuthError)
	ErrorNoReturnURI              = NewOAuthError("3006", "cannot find return uri", http.StatusBadRequest, http.StatusText(http.StatusBadRequest)).(*OAuthError)
	ErrorInsufficientClientInfo   = NewOAuthError("3007", "requested client info is insufficient", http.StatusBadRequest, http.StatusText(http.StatusBadRequest)).(*OAuthError)
	ErrorNoAllowedScope           = NewOAuthError("3008", "no scope allowed", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)).(*OAuthError)
)

func HttpRespond(w http.ResponseWriter, status int, err error) {
	w.WriteHeader(status)
	switch err := err.(type) {
	case *OAuthError:
		data := err.ResponseData()
		json.NewEncoder(w).Encode(data)
	default:
		data := make(map[string]interface{})
		data["error"] = http.StatusText(status)
		data["error_description"] = err.Error()
		json.NewEncoder(w).Encode(data)
		// http.Error(w, err.Error(), status)
	}

}
