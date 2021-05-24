package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/spf13/viper"
	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/deliveries"
	"github.com/wonksing/oauth-server/pkg/deliveries/dcommon"

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
	oauthServer.Srv.SetPasswordAuthorizationHandler(func(username, password string) (userID string, err error) {
		if username == "test" && password == "test" {
			userID = "test"
		}
		return
	})

	// Authorization Code Grant
	oauthServer.Srv.SetUserAuthorizationHandler(deliveries.UserAuthorizeHandler)

	h := deliveries.ServerHandler{
		Srv:         oauthServer.Srv,
		JwtSecret:   jwtSecret,
		ClientStore: oauthServer.ClientStore,
	}

	// 테스트용 API
	http.HandleFunc(deliveries.API_INDEX, dcommon.AuthJWTHandler(h.HelloHandler, jwtSecret, deliveries.API_LOGIN))
	http.HandleFunc(deliveries.API_HELLO, dcommon.AuthJWTHandler(h.HelloHandler, jwtSecret, deliveries.API_LOGIN))
	http.HandleFunc(deliveries.API_LOGIN, h.LoginHandler)

	// OAuth2 API
	// 리소스 서버에 인증
	http.HandleFunc(deliveries.API_OAUTH_LOGIN, h.OAuthLoginHandler)
	// 리소스 서버의 정보 인가
	http.HandleFunc(deliveries.API_OAUTH_ALLOW, dcommon.AuthJWTHandler(h.OAuthAllowAuthorizationHandler, jwtSecret, deliveries.API_OAUTH_LOGIN))
	// Authorization Code Grant Type
	http.HandleFunc(deliveries.API_OAUTH_AUTHORIZE, dcommon.AuthJWTHandler(h.OAuthAuthorizeHandler, jwtSecret, deliveries.API_OAUTH_LOGIN))

	// token request for all types of grant
	// Client Credentials Grant comes here directly
	// Client Server용 API
	http.HandleFunc(deliveries.API_OAUTH_TOKEN, h.OAuthTokenHandler)

	// validate access token
	http.HandleFunc(deliveries.API_OAUTH_TOKEN_VALIDATE, h.OAuthValidateTokenHandler)

	// client credential 저장
	http.HandleFunc(deliveries.API_OAUTH_CREDENTIALS, h.CredentialHandler)

	log.Printf("Server is running at %v.\n", addr)
	log.Printf("Point your OAuth client Auth endpoint to %s%s", "http://"+addr, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s%s", "http://"+addr, "/oauth/token")
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%v", addr), nil))
}
