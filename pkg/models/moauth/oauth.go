package moauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/wonksing/oauth-server/pkg/models/mjwt"
)

const (
	KeyReturnURI   = "oauth_return_uri"
	KeyAccessToken = "oauth_access_token"
	KeyRedirectURI = "oauth_redirect_uri"
)

// UserAuthorizeHandler 인가된 사용자인지 확인한다.
// 로그인된 사용자라면 사용자 아이디를 반환하고, 그렇지 않으면 로그인 페이지로 유도한다.
// GET /oauth/authorize?client_id=12345&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8%3D&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A9094%2Foauth2&response_type=code&scope=all&state=xyz
func UserAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	// commons.DumpRequest(os.Stdout, "UserAuthorizeHandler", r) // Ignore the error

	tc := mjwt.GetTokenClaimContext(r.Context())
	if tc == nil {
		err = errors.New("not authorized")
		return
	}
	userID = tc.UsrID
	if strings.TrimSpace(userID) == "" {
		err = errors.New("not authorized")
		return
	}
	return
}
func PasswordAuthorizeHandler(username, password string) (userID string, err error) {
	if username == "test" && password == "test" {
		userID = "test"
	}
	return
}

type Error interface {
	// ReplaceError(err error) (string, string)
	error
}
type OAuthError struct {
	ErrMsg  string
	ErrCode string
}

func NewOAuthError(errCode, errMsg string) Error {
	return &OAuthError{
		ErrMsg:  errMsg,
		ErrCode: errCode,
	}
}

func (o *OAuthError) Error() string {
	return "(" + o.ErrCode + ")" + o.ErrMsg
}

var (
	ErrorUserNeedToAllow = NewOAuthError("1000", "사용자의 권한 허용이 필요합니다").(*OAuthError)
	ErrorUserDidNotAllow = NewOAuthError("1001", "사용자가 권한 사용을 허용하지 않았습니다").(*OAuthError)
)
