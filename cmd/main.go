package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/spf13/viper"
	"github.com/wonksing/oauth-server/pkg/adaptors/cookies"
	"github.com/wonksing/oauth-server/pkg/adaptors/filerepo"
	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/deliveries/dmiddleware"
	"github.com/wonksing/oauth-server/pkg/deliveries/doauth"
	"github.com/wonksing/oauth-server/pkg/deliveries/duser"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/usecases/uoauth"

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

	// Password credentials
	oauthServer.Srv.SetPasswordAuthorizationHandler(moauth.PasswordAuthorizeHandler)

	// Authorization Code Grant
	oauthServer.Srv.SetUserAuthorizationHandler(moauth.UserAuthorizeHandler)

	oauthCookie := cookies.NewOAuthCookie("oauth_return_uri", time.Duration(24*365), "access_token", time.Duration(24*365))
	authRepo := filerepo.NewAuthFileRepo()

	oauthUsc := uoauth.NewOAuthUsecase(jwtSecret, oauthCookie, authRepo)

	oauthHandler := doauth.NewOAuthHandler(oauthUsc, oauthServer.Srv, jwtSecret, oauthServer.ClientStore)

	userHandler := duser.NewHttpUserHandler(jwtSecret)

	// 테스트용 API
	http.HandleFunc(duser.API_INDEX, userHandler.IndexHandler)
	http.HandleFunc(duser.API_LOGIN, userHandler.LoginHandler)
	http.HandleFunc(duser.API_AUTHENTICATE, userHandler.AuthenticateHandler)
	http.HandleFunc(duser.API_HELLO, dmiddleware.AuthJWTHandler(userHandler.HelloHandler, jwtSecret, duser.API_LOGIN))

	// OAuth2 API
	// 리소스 서버에 인증
	http.HandleFunc(doauth.API_OAUTH_LOGIN, oauthHandler.OAuthLoginHandler)
	http.HandleFunc(doauth.API_OAUTH_AUTHENTICATE, oauthHandler.OAuthAuthenticateHandler)
	// 리소스 서버의 정보 인가
	http.HandleFunc(doauth.API_OAUTH_ALLOW, dmiddleware.AuthJWTHandler(oauthHandler.OAuthAllowHandler, jwtSecret, doauth.API_OAUTH_LOGIN))
	// Authorization Code Grant Type
	http.HandleFunc(doauth.API_OAUTH_AUTHORIZE, dmiddleware.AuthJWTHandler(oauthHandler.OAuthAuthorizeHandler, jwtSecret, doauth.API_OAUTH_LOGIN))

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
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%v", addr), nil))
}
