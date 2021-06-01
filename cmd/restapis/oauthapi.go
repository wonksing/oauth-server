package restapis

import (
	"github.com/gorilla/mux"
	"github.com/wonksing/oauth-server/pkg/deliveries/doauth"
)

const (
	API_OAUTH_LOGIN              = "/oauth/login"               // present login page
	API_OAUTH_LOGIN_AUTHENTICATE = "/oauth/login/_authenticate" // validate user id and password
	API_OAUTH_LOGIN_ACCESS       = "/oauth/login/access"        // present access page
	// API_OAUTH_LOGIN_ACCESS_AUTHORIZE = "/oauth/login/access/_authorize" // authorize access
	API_OAUTH_AUTHORIZE = "/oauth/authorize" // oauth code grant

	API_OAUTH_TOKEN          = "/oauth/token"
	API_OAUTH_TOKEN_VALIDATE = "/oauth/token/_validate"
	API_OAUTH_CREDENTIALS    = "/oauth/credentials"
)
const (
	HTML_OAUTH_LOGIN  = "static/oauth/login.html"
	HTML_OAUTH_ACCESS = "static/oauth/access.html"
)

func RegisterOAuthAPIs(router *mux.Router, handler *doauth.OAuthHandler) {

	// OAuth2 API
	// 리소스 서버에 인증하러 보내기
	router.HandleFunc(API_OAUTH_LOGIN, handler.LoginHandler).Methods("GET")
	// 리소스 서버에서 인증하기
	router.HandleFunc(API_OAUTH_LOGIN_AUTHENTICATE, handler.AuthenticateHandler).Methods("POST")
	// 리소스 서버의 정보 인가하러 보내기
	router.HandleFunc(API_OAUTH_LOGIN_ACCESS, handler.AccessHandler).Methods("GET")
	// Authorization Code Grant Type
	router.HandleFunc(API_OAUTH_AUTHORIZE, handler.GrantAuthorizeCodeHandler).Methods("POST", "GET")

	// token request for all types of grant
	// Client Credentials Grant comes here directly
	// Client Server용 API
	router.HandleFunc(API_OAUTH_TOKEN, handler.OAuthTokenHandler).Methods("POST", "GET")

	// validate access token
	router.HandleFunc(API_OAUTH_TOKEN_VALIDATE, handler.OAuthValidateTokenHandler).Methods("POST", "GET")

	// client credential 저장
	router.HandleFunc(API_OAUTH_CREDENTIALS, handler.CredentialHandler).Methods("PUT")
}
