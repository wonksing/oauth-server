package main

import (
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
	"github.com/wonksing/oauth-server/pkg/port"
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
	API_OAUTH_LOGIN              = "/oauth/login"               // present login page
	API_OAUTH_LOGIN_AUTHENTICATE = "/oauth/login/_authenticate" // validate user id and password
	API_OAUTH_LOGIN_ACCESS       = "/oauth/login/access"        // present access page
	// API_OAUTH_LOGIN_ACCESS_AUTHORIZE = "/oauth/login/access/_authorize" // authorize access
	API_OAUTH_AUTHORIZE = "/oauth/authorize" // oauth code grant

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

	jwtSecret := conf.GetString("app.jwt_secret")
	jwtExpiresSecond := conf.GetInt64("app.jwt_expires_second")

	remoteAuth := conf.GetBool("oauth.remote.authenticate")
	remoteAuthURI := conf.GetString("oauth.remote.authenticate_uri")
	remoteRedirectURI := conf.GetString("oauth.remote.redirect_uri")

	jwtAccessToken := conf.GetBool("token_config.jwt_access_token") // oauth access token을 jwt 포맷으로 생성
	oAuthJwtSecret := conf.GetString("token_config.jwt_secret")
	// oAuthJwtExpiresSecond := conf.GetInt64("token_config.jwt_expires_second")
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
		tokenStoreFilePath, jwtAccessToken, oAuthJwtSecret)
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

		// _, scope, err := moauth.GetAuthResources(mapScopes, tgr.Scope)
		// if err != nil {
		// 	allowed = false
		// 	return
		// }
		// allowed = true
		// tgr.Scope = scope

		allowed = true
		err = nil

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
	var authRepo port.AuthRepo
	if remoteAuth {
		authRepo = repositories.NewOAuthRemoteRepo(
			oauthCookie,
			jwtSecret,
			jwtExpiresSecond,
			remoteAuthURI,
			"",
			remoteRedirectURI,
		)
	} else {
		authRepo = repositories.NewOAuthSelfRepo(
			oauthCookie,
			jwtSecret,
			API_OAUTH_LOGIN,
			API_OAUTH_LOGIN_ACCESS,
		)
	}
	authView := views.NewOAuthSelfView(
		HTML_OAUTH_LOGIN,
		HTML_OAUTH_ACCESS,
	)
	resRepo := repositories.NewOAuthUserRepo()

	oauthUsc := uoauth.NewOAuthUsecase(oauthServer, jwtSecret, jwtExpiresSecond,
		oauthCookie, authRepo, authView, resRepo,
	)

	oauthHandler := doauth.NewOAuthHandler(oauthUsc)
	userHandler := duser.NewHttpUserHandler(jwtSecret, jwtExpiresSecond)
	jwtMiddleware := dmiddleware.NewJWTMiddleware(jwtSecret, moauth.KeyAccessToken, oauthUsc)

	httpServer := commons.NewHttpServer(addr, 30, 30, "", "", nil, nil, nil)

	// 테스트용 API
	httpServer.Router.HandleFunc(duser.API_INDEX, userHandler.IndexHandler).Methods("GET")
	httpServer.Router.HandleFunc(duser.API_LOGIN, userHandler.LoginHandler).Methods("GET")
	httpServer.Router.HandleFunc(duser.API_AUTHENTICATE, userHandler.AuthenticateHandler).Methods("POST")
	httpServer.Router.HandleFunc(duser.API_HELLO, jwtMiddleware.AuthJWTHandler(userHandler.HelloHandler, duser.API_LOGIN)).Methods("GET")

	// OAuth2 API
	// 리소스 서버에 인증하러 보내기
	httpServer.Router.HandleFunc(API_OAUTH_LOGIN, oauthHandler.LoginHandler).Methods("GET")
	// 리소스 서버에서 인증하기
	httpServer.Router.HandleFunc(API_OAUTH_LOGIN_AUTHENTICATE, oauthHandler.AuthenticateHandler).Methods("POST")
	// 리소스 서버의 정보 인가하러 보내기
	httpServer.Router.HandleFunc(API_OAUTH_LOGIN_ACCESS, oauthHandler.AccessHandler).Methods("GET")
	// Authorization Code Grant Type
	httpServer.Router.HandleFunc(API_OAUTH_AUTHORIZE, oauthHandler.GrantAuthorizeCodeHandler).Methods("POST", "GET")

	// token request for all types of grant
	// Client Credentials Grant comes here directly
	// Client Server용 API
	httpServer.Router.HandleFunc(API_OAUTH_TOKEN, oauthHandler.OAuthTokenHandler).Methods("POST", "GET")

	// validate access token
	httpServer.Router.HandleFunc(API_OAUTH_TOKEN_VALIDATE, oauthHandler.OAuthValidateTokenHandler).Methods("POST", "GET")

	// client credential 저장
	httpServer.Router.HandleFunc(API_OAUTH_CREDENTIALS, oauthHandler.CredentialHandler).Methods("PUT")

	log.Printf("Server is running at %v.\n", addr)
	log.Printf("Point your OAuth client Auth endpoint to %s%s", "http://"+addr, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s%s", "http://"+addr, "/oauth/token")

	startSyscallChecker(httpServer)

	err = httpServer.Start()
	if err != nil {
		log.Println(err)
	}

	// ticker.Stop()
}

func startSyscallChecker(httpServer *commons.HttpServer) {

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		switch sig {
		case syscall.SIGINT:
			log.Println("syscall.SIGINT")
		case syscall.SIGTERM:
			log.Println("syscall.SIGTERM")
		default:
			log.Println(sig)
		}
		httpServer.Stop()
	}()
}
