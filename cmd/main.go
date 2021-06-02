package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	oauthErrors "github.com/go-oauth2/oauth2/v4/errors"

	"github.com/spf13/viper"
	"github.com/wonksing/oauth-server/cmd/restapis"
	"github.com/wonksing/oauth-server/pkg/adaptors/cookies"
	"github.com/wonksing/oauth-server/pkg/adaptors/repositories"
	"github.com/wonksing/oauth-server/pkg/adaptors/views"
	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/deliveries/doauth"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/port"
	"github.com/wonksing/oauth-server/pkg/usecases/uoauth"

	"github.com/go-oauth2/oauth2/v4"
	log "github.com/sirupsen/logrus"
)

var (
	Version         = "v1.1.10"
	printVersion    = false
	tickIntervalSec = 30

	dumpvar bool
	// idvar     string
	// secretvar string
	// domainvar string
	// portvar   int

	addr           string
	cert           string
	certKey        string
	wt             int
	rt             int
	configFileName string
	loggerFileName string
)

// const (
// 	API_OAUTH_LOGIN              = "/oauth/login"               // present login page
// 	API_OAUTH_LOGIN_AUTHENTICATE = "/oauth/login/_authenticate" // validate user id and password
// 	API_OAUTH_LOGIN_ACCESS       = "/oauth/login/access"        // present access page
// 	// API_OAUTH_LOGIN_ACCESS_AUTHORIZE = "/oauth/login/access/_authorize" // authorize access
// 	API_OAUTH_AUTHORIZE = "/oauth/authorize" // oauth code grant

// 	API_OAUTH_TOKEN          = "/oauth/token"
// 	API_OAUTH_TOKEN_VALIDATE = "/oauth/token/_validate"
// 	API_OAUTH_CREDENTIALS    = "/oauth/credentials"

// 	HTML_OAUTH_LOGIN  = "static/oauth/login.html"
// 	HTML_OAUTH_ACCESS = "static/oauth/access.html"
// )

func init() {
	flag.StringVar(&addr, "addr", ":9096", "listening address(eg. :9096)")
	flag.StringVar(&cert, "cert", "", "certificate file path")
	flag.StringVar(&certKey, "key", "", "key file path")
	flag.IntVar(&wt, "wt", 30, "write timeout in second")
	flag.IntVar(&rt, "rt", 30, "read timeout in second")
	flag.StringVar(&configFileName, "conf", "./configs/server.yml", "config file name")
	flag.StringVar(&loggerFileName, "logger", "./configs/logger.yml", "logger config file name")
	flag.BoolVar(&dumpvar, "d", true, "Dump requests and responses")

	flag.BoolVar(&printVersion, "version", false, "print version")
	flag.IntVar(&tickIntervalSec, "tick", 60, "tick interval in second")

}

func initLogger() {
	// 로깅 설정 로딩
	logInJSON := false
	logStdOut := false
	logFilNam := "./logs/agent.log"
	logMaxSiz := 50
	logMaxBup := 50
	logMaxAge := 31
	logCompressed := true
	logLvl := "info"

	loggerConfig := viper.New()
	loggerConfig.SetConfigFile(loggerFileName)
	err := loggerConfig.ReadInConfig()
	if err == nil {
		logInJSON = loggerConfig.GetBool("logger.json")
		logStdOut = loggerConfig.GetBool("logger.stdout")
		logFilNam = loggerConfig.GetString("logger.file.name")
		logMaxSiz = loggerConfig.GetInt("logger.file.max_size")
		logMaxBup = loggerConfig.GetInt("logger.file.max_backup")
		logMaxAge = loggerConfig.GetInt("logger.file.max_age")
		logCompressed = loggerConfig.GetBool("logger.file.compressed")
		logLvl = loggerConfig.GetString("logger.level")
	}
	commons.InitLogrus(logStdOut, logInJSON, logFilNam, logMaxSiz, logMaxBup, logMaxAge, logCompressed, logLvl)

}

func getClientCredentialsFromConfig(clientCredentialMap map[string]interface{}) moauth.OAuthClientList {
	list := make(moauth.OAuthClientList, 0)
	for _, val := range clientCredentialMap {
		v := val.(map[string]interface{})
		id := v["id"].(string)
		secret := v["secret"].(string)
		domain := v["domain"].(string)
		scope := v["scope"].(string)
		list = append(list, &moauth.OAuthClient{
			ID:     id,
			Secret: secret,
			Domain: domain,
			Scope:  scope,
		})
	}
	return list
}

func getAllowedGrantTypesFromConfig(grantTypeConf string) []oauth2.GrantType {
	allowedGrantTypeList := strings.Split(grantTypeConf, ",")
	grantTypes := make([]oauth2.GrantType, 0)
	for _, v := range allowedGrantTypeList {
		if v == "authorization_code" {
			grantTypes = append(grantTypes, oauth2.AuthorizationCode)
		} else if v == "client_credentials" {
			grantTypes = append(grantTypes, oauth2.ClientCredentials)
		} else if v == "password" {
			grantTypes = append(grantTypes, oauth2.PasswordCredentials)
		} else if v == "refresh_token" {
			grantTypes = append(grantTypes, oauth2.Refreshing)
		}

	}
	return grantTypes
}

func main() {

	flag.Parse()
	if printVersion {
		fmt.Printf("oauth-server version \"%v\"\n", Version)
		return
	}

	if dumpvar {
		log.Println("Dumping requests")
	}

	initLogger()

	conf := viper.New()
	conf.SetConfigFile(configFileName)
	err := conf.ReadInConfig()
	if err != nil {
		// log.WithFields(commons.LogrusFields()).Infof("NoOfGR:%v, %v", runtime.NumGoroutine(), t)
		log.WithFields(commons.LogrusFields()).Error(err)
		return
	}

	jwtSecret := conf.GetString("app.jwt_secret")
	jwtExpiresSecond := conf.GetInt64("app.jwt_expires_second")

	allowedGrantType := conf.GetString("oauth.allowed_grant_type")
	remoteAuth := conf.GetBool("oauth.remote.authenticate")
	remoteAuthURI := conf.GetString("oauth.remote.authenticate_uri")
	remoteRedirectURI := conf.GetString("oauth.remote.redirect_uri")

	returnURIKey := conf.GetString("oauth.cookie.return_uri_key")
	returnURIExp := conf.GetInt("oauth.cookie.return_uri_expires_in")
	accessTokenKey := conf.GetString("oauth.cookie.access_token_key")
	accessTokenExp := conf.GetInt("oauth.cookie.access_token_expires_in")
	redirectURIKey := conf.GetString("oauth.cookie.redirect_uri_key")
	redirectURIExp := conf.GetInt("oauth.cookie.redirect_uri_expires_in")

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
	clientCredentialMap := cc.AllSettings()

	grantTypes := getAllowedGrantTypesFromConfig(allowedGrantType)
	clientCredentials := getClientCredentialsFromConfig(clientCredentialMap)

	oauthServer := commons.NewOAuthServer(
		authCodeAccessTokenExp, authCodeRefreshTokenExp, authCodeGenerateRefresh,
		clientCredentialsAccessTokenExp, clientCredentialsRefreshTokenExp, clientCredentialsGenerateRefresh,
		tokenStoreFilePath, jwtAccessToken, oAuthJwtSecret, grantTypes, clientCredentials,
	)

	// TODO Scope 모델 정의
	mapScopes := make(map[string]string)
	mapScopes["item"] = "/item,/item/new,/item/_add,/item/_delete"
	mapScopes["item:read"] = "/item,/item/new"
	mapScopes["item:new:read"] = "/item,/item/new"
	mapScopes["item:write"] = "/item/_add"
	mapScopes["emp"] = "/emp,/emp/new,/emp/_add"

	oauthServer.Srv.SetResponseErrorHandler(func(re *oauthErrors.Response) {
		// 오류 응답은 다음과 같은 json 포맷으로 통일하도록 하자
		// {"error":"unauthorized_client","error_description":"The client is not authorized to request an authorization code using this method"}
		log.WithFields(commons.LogrusFields()).Error(re.Error)
		// if re.Error == merror.ErrorNotAllowedScop {
		// 	re.StatusCode = http.StatusUnauthorized
		// 	re.Description = http.StatusText(http.StatusUnauthorized)
		// }
	})
	oauthServer.Srv.SetAuthorizeScopeHandler(func(w http.ResponseWriter, r *http.Request) (scope string, err error) {
		// authorization code 를 요청할 때, 요청 파라메터의 client_id와 scope를 이용해서
		// 허용된 scope을 구해야 한다.

		// scope = "item:new:read"

		if r.Form == nil {
			r.ParseForm()
		}
		scope = r.Form.Get("scope")
		return
	})
	oauthServer.Srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error) {
		// 모든 Grant Type을 통해 Token을 요청할 때,

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
		returnURIKey,
		time.Duration(returnURIExp)*time.Hour,
		accessTokenKey,
		time.Duration(accessTokenExp)*time.Hour,
		redirectURIKey,
		time.Duration(redirectURIExp)*time.Hour,
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
			restapis.API_OAUTH_LOGIN,
			restapis.API_OAUTH_LOGIN_ACCESS,
		)
	}
	authView := views.NewOAuthSelfView(
		restapis.HTML_OAUTH_LOGIN,
		restapis.HTML_OAUTH_ACCESS,
	)
	resRepo := repositories.NewOAuthUserRepo()

	oauthUsc := uoauth.NewOAuthUsecase(
		oauthServer,
		jwtSecret, jwtExpiresSecond,
		authRepo, authView, resRepo,
	)

	oauthHandler := doauth.NewOAuthHandler(oauthUsc)
	// jwtMiddleware := dmiddleware.NewJWTMiddleware(jwtSecret, moauth.KeyAccessToken, oauthUsc)
	httpServer := commons.NewHttpServer(addr, wt, rt, cert, certKey, nil, nil, nil)

	// OAuth2 API
	restapis.RegisterOAuthAPIs(httpServer.Router, oauthHandler)

	log.WithFields(commons.LogrusFields()).Infof("Server is running at %v.\n", addr)
	log.WithFields(commons.LogrusFields()).Infof("Point your OAuth client Auth endpoint to %s%s", "http://"+addr, "/oauth/authorize")
	log.WithFields(commons.LogrusFields()).Infof("Point your OAuth client Token endpoint to %s%s", "http://"+addr, "/oauth/token")

	startSyscallChecker(httpServer)

	err = httpServer.Start()
	if err != nil {
		log.WithFields(commons.LogrusFields()).Error(err)
	}

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
