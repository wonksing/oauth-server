package moauth

import (
	"net/http"

	"github.com/wonksing/oauth-server/pkg/models/mjwt"
)

const (
	KeyReturnURI = "oauth_return_uri"
)

// UserAuthorizeHandler 인가된 사용자인지 확인한다.
// 로그인된 사용자라면 사용자 아이디를 반환하고, 그렇지 않으면 로그인 페이지로 유도한다.
// GET /oauth/authorize?client_id=12345&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8%3D&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A9094%2Foauth2&response_type=code&scope=all&state=xyz
func UserAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	// commons.DumpRequest(os.Stdout, "UserAuthorizeHandler", r) // Ignore the error

	ctx := r.Context()
	claim := ctx.Value(mjwt.TokenClaim{})
	tc := claim.(*mjwt.TokenClaim)
	userID = tc.UsrID

	return
}
func PasswordAuthorizeHandler(username, password string) (userID string, err error) {
	if username == "test" && password == "test" {
		userID = "test"
	}
	return
}
