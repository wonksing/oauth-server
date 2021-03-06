package dmiddleware

import (
	"errors"
	"net/http"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/mjwt"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/usecases/uoauth"
)

type JWTMiddleware struct {
	jwtSecret      string
	accessTokenKey string
	oauthUsc       uoauth.Usecase
}

func NewJWTMiddleware(jwtSecret, accessTokenKey string, oauthUsc uoauth.Usecase) *JWTMiddleware {
	return &JWTMiddleware{
		jwtSecret:      jwtSecret,
		accessTokenKey: accessTokenKey,
		oauthUsc:       oauthUsc,
	}
}

func authJWT(r *http.Request, secretKey, accessTokenKey string) (*mjwt.TokenClaim, error) {

	ck, err := r.Cookie(accessTokenKey)
	if err != nil || ck.Value == "" {
		return nil, errors.New("no valid access_token")
	}

	token := ck.Value
	claim, _, err := mjwt.ValidateAccessToken(token, secretKey)

	if err != nil || claim == nil {
		return nil, errors.New(http.StatusText(http.StatusUnauthorized))
	}

	return claim, nil
}

// AuthJWTHandler to verify the request
func (m *JWTMiddleware) AuthJWTHandler(next http.HandlerFunc, redirectUriOnFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		claim, err := authJWT(r, m.jwtSecret, m.accessTokenKey)
		if err != nil {
			commons.Redirect(w, redirectUriOnFail)
			return
		}
		ctx := mjwt.WithTokenClaimContext(r.Context(), claim)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// OAuthAuthJWTHandler to verify the request
func (m *JWTMiddleware) OAuthAuthJWTHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		claim, err := authJWT(r, m.jwtSecret, m.accessTokenKey)
		if err != nil {
			err = m.oauthUsc.RedirectToLogin(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
		ctx := mjwt.WithTokenClaimContext(r.Context(), claim)
		ctx = moauth.WithUserIDContext(ctx, claim.UsrID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
