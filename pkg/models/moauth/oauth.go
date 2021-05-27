package moauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

const (
	KeyReturnURI   = "oauth_return_uri"
	KeyAccessToken = "oauth_access_token"
	KeyRedirectURI = "oauth_redirect_uri"
)

type OAuthUserID struct {
}
type OAuthAllowStatus struct {
}

func GetUserIDContext(ctx context.Context) (string, error) {
	tmp := ctx.Value(OAuthUserID{})
	if tmp == nil || tmp.(string) == "" {
		return "", ErrorUserIDNotFound
	}

	return tmp.(string), nil
}

func WithUserIDContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, OAuthUserID{}, userID)
}

func GetAllowStatus(ctx context.Context) (string, error) {
	tmp := ctx.Value(OAuthAllowStatus{})
	if tmp == nil || tmp.(string) == "" {
		return "", ErrorUserNeedToAllow
	}
	if tmp != "yes" {
		return "", ErrorUserDidNotAllow
	}
	return tmp.(string), nil
}

func WithAllowStatusContext(ctx context.Context, status string) context.Context {
	return context.WithValue(ctx, OAuthAllowStatus{}, status)
}

// UserAuthorizeHandler 인가된 사용자인지 확인한다.
// 로그인된 사용자라면 사용자 아이디를 반환하고, 그렇지 않으면 로그인 페이지로 유도한다.
// GET /oauth/authorize?client_id=12345&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8%3D&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A9094%2Foauth2&response_type=code&scope=all&state=xyz
func UserAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	// commons.DumpRequest(os.Stdout, "UserAuthorizeHandler", r) // Ignore the error

	userID, err = GetUserIDContext(r.Context())
	if strings.TrimSpace(userID) == "" {
		userID = ""
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
	ErrorUserIDNotFound  = NewOAuthError("1002", "사용자 아이디가 없습니다").(*OAuthError)
	ErrorUserNeedToAllow = NewOAuthError("1000", "사용자의 권한 허용이 필요합니다").(*OAuthError)
	ErrorUserDidNotAllow = NewOAuthError("1001", "사용자가 권한 사용을 거절하였습니다").(*OAuthError)
)
