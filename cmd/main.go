package main

import (
	"errors"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	oauthErrors "github.com/go-oauth2/oauth2/v4/errors"

	"github.com/spf13/viper"
	"github.com/wonksing/oauth-server/pkg/adaptors/cookies"
	"github.com/wonksing/oauth-server/pkg/adaptors/repositories"
	"github.com/wonksing/oauth-server/pkg/adaptors/views"
	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/deliveries/dmiddleware"
	"github.com/wonksing/oauth-server/pkg/deliveries/doauth"
	"github.com/wonksing/oauth-server/pkg/deliveries/duser"
	"github.com/wonksing/oauth-server/pkg/models/merror"
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

const (
	API_OAUTH_LOGIN                  = "/oauth/login"                   // present login page
	API_OAUTH_LOGIN_AUTHENTICATE     = "/oauth/login/_authenticate"     // validate user id and password
	API_OAUTH_LOGIN_ACCESS           = "/oauth/login/access"            // present access page
	API_OAUTH_LOGIN_ACCESS_AUTHORIZE = "/oauth/login/access/_authorize" // authorize access
	API_OAUTH_AUTHORIZE              = "/oauth/authorize"               // oauth code grant

	API_OAUTH_TOKEN          = "/oauth/token"
	API_OAUTH_TOKEN_VALIDATE = "/oauth/token/_validate"
	API_OAUTH_CREDENTIALS    = "/oauth/credentials"

	HTML_OAUTH_LOGIN  = "static/oauth/login.html"
	HTML_OAUTH_ACCESS = "static/oauth/access.html"
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

	// TODO Scope 모델 정의
	mapScopes := make(map[string]string)
	mapScopes["item"] = "/item,/item/new,/item/_add,/item/_delete"
	mapScopes["item:read"] = "/item,/item/new"
	mapScopes["item:new:read"] = "/item,/item/new"
	mapScopes["item:write"] = "/item/_add"
	mapScopes["emp"] = "/emp,/emp/new,/emp/_add"

	oauthServer.Srv.SetResponseErrorHandler(func(re *oauthErrors.Response) {
		log.Println(re.Error)
		if re.Error == merror.ErrorNotAllowedScop {
			re.StatusCode = http.StatusUnauthorized
			re.Description = http.StatusText(http.StatusUnauthorized)
		}
	})
	oauthServer.Srv.SetAuthorizeScopeHandler(func(w http.ResponseWriter, r *http.Request) (scope string, err error) {
		// authorization code grant type일때 범위
		// scope = "item:new:read"

		if r.Form == nil {
			r.ParseForm()
		}
		scope = r.Form.Get("scope")
		return
	})
	oauthServer.Srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error) {
		// client credential grant type일때 범위

		_, scope, err := moauth.GetAuthResources(mapScopes, tgr.Scope)
		if err != nil {
			allowed = false
			return
		}
		allowed = true
		tgr.Scope = scope

		return
	})
	// Authorization Code Grant
	oauthServer.Srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID, err = moauth.GetUserIDContext(r.Context())
		if strings.TrimSpace(userID) == "" {
			userID = ""
			err = errors.New("not authorized")
			return
		}
		return
	})

	// Password credentials
	oauthServer.Srv.SetPasswordAuthorizationHandler(func(username, password string) (userID string, err error) {
		// if username == password && username == "TTesTT" {
		// 	userID = username
		// }
		err = errors.New("not supported")
		return
	})

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
		API_OAUTH_LOGIN,
		API_OAUTH_LOGIN_ACCESS,
	)
	authView := views.NewOAuthSelfView(
		HTML_OAUTH_LOGIN,
		HTML_OAUTH_ACCESS,
	)
	oauthUsc := uoauth.NewOAuthUsecase(oauthServer, jwtSecret, 360, authRepo, authView)

	oauthHandler := doauth.NewOAuthHandler(oauthUsc, jwtSecret)
	userHandler := duser.NewHttpUserHandler(jwtSecret, 360)
	jwtMiddleware := dmiddleware.NewJWTMiddleware(jwtSecret, moauth.KeyAccessToken, oauthUsc)

	// 테스트용 API
	http.HandleFunc(duser.API_INDEX, userHandler.IndexHandler)
	http.HandleFunc(duser.API_LOGIN, userHandler.LoginHandler)
	http.HandleFunc(duser.API_AUTHENTICATE, userHandler.AuthenticateHandler)
	http.HandleFunc(duser.API_HELLO, jwtMiddleware.AuthJWTHandler(userHandler.HelloHandler, duser.API_LOGIN))

	// OAuth2 API
	// 리소스 서버에 인증하러 보내기
	http.HandleFunc(API_OAUTH_LOGIN, oauthHandler.LoginHandler)
	// 리소스 서버에서 인증하기
	http.HandleFunc(API_OAUTH_LOGIN_AUTHENTICATE, oauthHandler.AuthenticateHandler)
	// 리소스 서버의 정보 인가하러 보내기
	http.HandleFunc(API_OAUTH_LOGIN_ACCESS, jwtMiddleware.OAuthAuthJWTHandler(oauthHandler.AccessHandler))
	http.HandleFunc(API_OAUTH_LOGIN_ACCESS_AUTHORIZE, jwtMiddleware.OAuthAuthJWTHandler(oauthHandler.AuthorizeAccessHandler))
	// Authorization Code Grant Type
	http.HandleFunc(API_OAUTH_AUTHORIZE, jwtMiddleware.OAuthAuthJWTHandler(oauthHandler.UserAuthorizeHandler))
	// http.HandleFunc("/oauth/authorize/redirect", oauthHandler.OAuthAuthorizeHandler)

	// token request for all types of grant
	// Client Credentials Grant comes here directly
	// Client Server용 API
	http.HandleFunc(API_OAUTH_TOKEN, oauthHandler.OAuthTokenHandler)

	// validate access token
	http.HandleFunc(API_OAUTH_TOKEN_VALIDATE, oauthHandler.OAuthValidateTokenHandler)

	// client credential 저장
	http.HandleFunc(API_OAUTH_CREDENTIALS, oauthHandler.CredentialHandler)

	log.Printf("Server is running at %v.\n", addr)
	log.Printf("Point your OAuth client Auth endpoint to %s%s", "http://"+addr, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s%s", "http://"+addr, "/oauth/token")
	log.Fatal(http.ListenAndServe(addr, nil))
}
