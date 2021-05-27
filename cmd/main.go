package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/spf13/viper"
	"github.com/wonksing/oauth-server/pkg/adaptors/cookies"
	"github.com/wonksing/oauth-server/pkg/adaptors/repositories"
	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/deliveries/dmiddleware"
	"github.com/wonksing/oauth-server/pkg/deliveries/doauth"
	"github.com/wonksing/oauth-server/pkg/deliveries/duser"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/usecases/uoauth"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
)

var (
	dumpvar bool
	// idvar     string
	// secretvar string
	// domainvar string
	// portvar   int

	addr           string
	configFileName string
)

func init() {
	flag.StringVar(&addr, "addr", ":9096", "listening address(eg. :9096)")
	flag.StringVar(&configFileName, "conf", "./configs/server.yml", "config file name")
	flag.BoolVar(&dumpvar, "d", true, "Dump requests and responses")
}

func main() {
	flag.Parse()
	if dumpvar {
		log.Println("Dumping requests")
	}

	conf := viper.New()
	conf.SetConfigFile(configFileName)
	err := conf.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}
	jwtAccessToken := conf.GetBool("token_config.jwt_access_token")
	jwtSecret := conf.GetString("token_config.jwt_secret")
	authCodeAccessTokenExp := conf.GetInt("token_config.auth_code.access_token_exp")
	authCodeRefreshTokenExp := conf.GetInt("token_config.auth_code.refresh_token_exp")
	authCodeGenerateRefresh := conf.GetBool("token_config.auth_code.generate_refresh")
	clientCredentialsAccessTokenExp := conf.GetInt("token_config.client_credential.access_token_exp")
	clientCredentialsRefreshTokenExp := conf.GetInt("token_config.client_credential.refresh_token_exp")
	clientCredentialsGenerateRefresh := conf.GetBool("token_config.client_credential.generate_refresh")

	tokenStoreFilePath := conf.GetString("token_store.file.path")

	cc := conf.Sub("client_credentials")
	ccSettings := cc.AllSettings()

	oauthServer := commons.NewOAuthServer(authCodeAccessTokenExp, authCodeRefreshTokenExp, authCodeGenerateRefresh,
		clientCredentialsAccessTokenExp, clientCredentialsRefreshTokenExp, clientCredentialsGenerateRefresh,
		tokenStoreFilePath, jwtAccessToken, jwtSecret)
	for _, val := range ccSettings {
		v := val.(map[string]interface{})
		id := v["id"].(string)
		secret := v["secret"].(string)
		domain := v["domain"].(string)
		oauthServer.ClientStore.Set(id, &models.Client{
			ID:     id,
			Secret: secret,
			Domain: domain,
		})
	}
	// oauthServer.Srv.SetResponseErrorHandler(func(re *oauthErrors.Response) {

	// })
	oauthServer.Srv.SetAuthorizeScopeHandler(func(w http.ResponseWriter, r *http.Request) (scope string, err error) {
		// authorization code grant type일때 범위
		scope = "authorization code"
		err = nil
		return
	})
	oauthServer.Srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error) {
		// client credential grant type일때 범위

		// if tgr.Scope == "all" {
		// 	allowed = false
		// 	return
		// }
		tgr.Scope = "client credential"
		allowed = true
		err = nil
		return
	})
	// Password credentials
	oauthServer.Srv.SetPasswordAuthorizationHandler(moauth.PasswordAuthorizeHandler)

	// Authorization Code Grant
	oauthServer.Srv.SetUserAuthorizationHandler(moauth.UserAuthorizeHandler)

	oauthCookie := cookies.NewOAuthCookie(
		moauth.KeyReturnURI,
		time.Duration(24*365),
		moauth.KeyAccessToken,
		time.Duration(24*365),
		moauth.KeyRedirectURI,
		time.Duration(24*365),
	)
	authRepo := repositories.NewOAuthSelfRepo(
		oauthCookie,
		doauth.API_OAUTH_LOGIN,
		doauth.API_OAUTH_LOGIN_ACCESS,
	)

	oauthUsc := uoauth.NewOAuthUsecase(oauthServer, jwtSecret, 360, authRepo)

	oauthHandler := doauth.NewOAuthHandler(oauthUsc, oauthServer.Srv, jwtSecret, oauthServer.ClientStore)
	userHandler := duser.NewHttpUserHandler(jwtSecret, 360)
	jwtMiddleware := dmiddleware.NewJWTMiddleware(jwtSecret, moauth.KeyAccessToken, oauthUsc)

	// 테스트용 API
	http.HandleFunc(duser.API_INDEX, userHandler.IndexHandler)
	http.HandleFunc(duser.API_LOGIN, userHandler.LoginHandler)
	http.HandleFunc(duser.API_AUTHENTICATE, userHandler.AuthenticateHandler)
	http.HandleFunc(duser.API_HELLO, jwtMiddleware.AuthJWTHandler(userHandler.HelloHandler, duser.API_LOGIN))

	// OAuth2 API
	// 리소스 서버에 인증하러 보내기
	http.HandleFunc(doauth.API_OAUTH_LOGIN, oauthHandler.LoginHandler)
	// 리소스 서버에서 인증하기
	http.HandleFunc(doauth.API_OAUTH_LOGIN_AUTHENTICATE, oauthHandler.AuthenticateHandler)
	// 리소스 서버의 정보 인가하러 보내기
	http.HandleFunc(doauth.API_OAUTH_LOGIN_ACCESS, jwtMiddleware.AuthJWTHandlerReturnURI(oauthHandler.AccessHandler))
	http.HandleFunc(doauth.API_OAUTH_LOGIN_ACCESS_AUTHORIZE, jwtMiddleware.AuthJWTHandlerReturnURI(oauthHandler.AuthorizeAccessHandler))
	// Authorization Code Grant Type
	http.HandleFunc(doauth.API_OAUTH_AUTHORIZE, jwtMiddleware.AuthJWTHandlerReturnURI(oauthHandler.UserAuthorizeHandler))
	// http.HandleFunc("/oauth/authorize/redirect", oauthHandler.OAuthAuthorizeHandler)

	// token request for all types of grant
	// Client Credentials Grant comes here directly
	// Client Server용 API
	http.HandleFunc(doauth.API_OAUTH_TOKEN, oauthHandler.OAuthTokenHandler)

	// validate access token
	http.HandleFunc(doauth.API_OAUTH_TOKEN_VALIDATE, oauthHandler.OAuthValidateTokenHandler)

	// client credential 저장
	http.HandleFunc(doauth.API_OAUTH_CREDENTIALS, oauthHandler.CredentialHandler)

	log.Printf("Server is running at %v.\n", addr)
	log.Printf("Point your OAuth client Auth endpoint to %s%s", "http://"+addr, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s%s", "http://"+addr, "/oauth/token")
	log.Fatal(http.ListenAndServe(addr, nil))
}
