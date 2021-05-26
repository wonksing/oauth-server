package dmiddleware

import (
	"errors"
	"net/http"

	"github.com/wonksing/oauth-server/pkg/models/mjwt"
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

		// if expired {
		// 	// refresh logic...
		// }
		// http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		// return errors.New(http.StatusText(http.StatusUnauthorized))
	}

	return claim, nil
}

// AuthJWTHandler to verify the request
func (m *JWTMiddleware) AuthJWTHandler(next http.HandlerFunc, redirectUriOnFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		claim, err := authJWT(r, m.jwtSecret, m.accessTokenKey)
		if err != nil {
			// if redirectUriOnFail == "/oauth/login" {
			// 	if r.Form == nil {
			// 		r.ParseForm()
			// 	}
			// 	commons.SetCookie(w, "oauth_return_uri", r.Form.Encode(), time.Duration(24*365))

			// }
			// commons.SetCookie(w, "access_token", "", time.Duration(24*365))

			// m.oauthUsc.ClearOAuthUserCookie(w)

			w.Header().Set("Location", redirectUriOnFail)
			w.WriteHeader(http.StatusFound)
			return
		}
		ctx := mjwt.WithTokenClaimContext(r.Context(), claim)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// AuthJWTHandler to verify the request
func (m *JWTMiddleware) AuthJWTHandlerReturnURI(next http.HandlerFunc, redirectUriOnFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		claim, err := authJWT(r, m.jwtSecret, m.accessTokenKey)
		if err != nil {
			// m.oauthUsc.SetReturnURI(w, r)
			// m.oauthUsc.SetRedirectURI(w, r)
			// w.Header().Set("Location", redirectUriOnFail)
			// w.WriteHeader(http.StatusFound)
			err = m.oauthUsc.SendToLogin(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
		ctx := mjwt.WithTokenClaimContext(r.Context(), claim)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
