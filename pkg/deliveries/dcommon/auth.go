package dcommon

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/wonksing/oauth-server/pkg/commons"
)

func handleJWTAuth(w http.ResponseWriter, r *http.Request, secretKey string) (*commons.TokenClaim, error) {

	ck, err := r.Cookie("access_token")
	if err != nil || ck.Value == "" {
		return nil, errors.New("no valid access_token")
	}

	token := ck.Value
	claim, _, err := commons.ValidateAccessToken(token, secretKey)

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
func AuthJWTHandler(next http.HandlerFunc, secret, redirectUriOnFail string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		claim, err := handleJWTAuth(w, r, secret)
		if err != nil {
			if redirectUriOnFail == "/oauth/login" {
				if r.Form == nil {
					r.ParseForm()
				}
				commons.SetCookie(w, "oauth_return_uri", r.Form.Encode(), time.Duration(24*365))
			}
			commons.SetCookie(w, "access_token", "", time.Duration(24*365))
			w.Header().Set("Location", redirectUriOnFail)
			w.WriteHeader(http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), commons.TokenClaim{}, claim)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
