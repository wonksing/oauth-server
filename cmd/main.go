package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wonksing/oauth-server/pkg/adaptors/authorizers"

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
	Version         = "v1.1.11"
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

func getScopesFromConfig(m map[string]interface{}) *moauth.OAuthScope {
	scopeMap := moauth.NewOAuthScope()
	for k, v := range m {

		list := make(moauth.AuthorizedResources, 0)
		resources := strings.Split(v.(string), ",")
		for _, r := range resources {
			ar := moauth.AuthorizedResource{}
			ar.Path = r
			tmp := strings.Split(k, ":")
			if len(tmp) == 1 {
				ar.Get = true
				ar.Post = true
				ar.Put = true
				ar.Delete = true
			} else {
				switch tmp[len(tmp)-1] {
				case "read":
					ar.Get = true
				case "update":
					ar.Post = true
				case "write":
					ar.Put = true
				case "delete":
					ar.Delete = true
				}
			}
			list = append(list, ar)
		}
		scopeMap.Set(k, list)
	}
	return scopeMap
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

	scopeViperSub := conf.Sub("scope")
	scopeConf := scopeViperSub.AllSettings()

	scopeMap := getScopesFromConfig(scopeConf)

	grantTypes := getAllowedGrantTypesFromConfig(allowedGrantType)
	clientCredentials := getClientCredentialsFromConfig(clientCredentialMap)

	oauthServer := commons.NewOAuthServer(
		authCodeAccessTokenExp, authCodeRefreshTokenExp, authCodeGenerateRefresh,
		clientCredentialsAccessTokenExp, clientCredentialsRefreshTokenExp, clientCredentialsGenerateRefresh,
		tokenStoreFilePath, jwtAccessToken, oAuthJwtSecret, grantTypes, clientCredentials,
	)

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

	oauth2Authorizer := authorizers.NewOAuth2Authorizer(oauthServer)

	oauthUsc := uoauth.NewOAuthUsecase(
		jwtSecret, jwtExpiresSecond,
		oauth2Authorizer,
		authRepo, authView, resRepo,
		scopeMap,
	)

	oauthHandler := doauth.NewOAuthHandler(oauthUsc)
	// jwtMiddleware := dmiddleware.NewJWTMiddleware(jwtSecret, moauth.KeyAccessToken, oauthUsc)
	httpServer := commons.NewHttpServer(addr, wt, rt, cert, certKey, nil, nil, nil)

	oauthServer.Srv.SetResponseErrorHandler(func(re *oauthErrors.Response) {
		// 오류 응답은 다음과 같은 json 포맷으로 통일하도록 하자
		// {"error":"unauthorized_client","error_description":"The client is not authorized to request an authorization code using this method"}
		log.WithFields(commons.LogrusFields()).Error(re.Error)
	})
	oauthServer.Srv.SetAuthorizeScopeHandler(oauthUsc.GrantedScope)
	oauthServer.Srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error) {
		// 모든 Grant Type을 통해 Token을 요청할 때, 발급한 토큰에 여기서 지정한 scope이 포함된다
		scope, err := oauthUsc.GrnatScopeByClient(tgr.ClientID, tgr.Scope)
		if err != nil {
			allowed = false
			return
		}
		allowed = true
		tgr.Scope = scope
		err = nil
		return
	})
	// Authorization Code Grant
	oauthServer.Srv.SetUserAuthorizationHandler(oauthUsc.GrantedUserID)

	// Password credentials
	oauthServer.Srv.SetPasswordAuthorizationHandler(oauthUsc.VerifyUserIDPW)

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
