package commons

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

type OAuthServer struct {
	ClientStore *store.ClientStore
	Manager     *manage.Manager
	Srv         *server.Server
}

func initClientStore() *store.ClientStore {
	return store.NewClientStore()
}
func initManager(clientStore *store.ClientStore,
	authCodeAccessTokenExp, authCodeRefreshTokenExp int, authCodeGenerateRefresh bool,
	clientCredentialsAccessTokenExp, clientCredentialsRefreshTokenExp int, clientCredentialsGenerateRefresh bool,
	tokenStoreFilePath string, jwtAccessToken bool, jwtSecret string) *manage.Manager {

	manager := manage.NewDefaultManager()
	// manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    time.Hour * time.Duration(authCodeAccessTokenExp),
		RefreshTokenExp:   time.Hour * time.Duration(authCodeRefreshTokenExp),
		IsGenerateRefresh: authCodeGenerateRefresh,
	})
	manager.SetClientTokenCfg(&manage.Config{
		AccessTokenExp:    time.Hour * time.Duration(clientCredentialsAccessTokenExp),
		RefreshTokenExp:   time.Hour * time.Duration(clientCredentialsRefreshTokenExp),
		IsGenerateRefresh: clientCredentialsGenerateRefresh,
	})

	// token store
	if tokenStoreFilePath != "" {
		manager.MustTokenStorage(store.NewFileTokenStore(tokenStoreFilePath))
	} else {
		// memory
		manager.MustTokenStorage(store.NewMemoryTokenStore())
	}

	// generate jwt access token
	if jwtAccessToken {
		manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte(jwtSecret), jwt.SigningMethodHS512))
	} else {
		manager.MapAccessGenerate(generates.NewAccessGenerate())
	}

	manager.MapClientStorage(clientStore)

	return manager
}

func initServer(manager *manage.Manager) *server.Server {
	srv := server.NewDefaultServer(manager)
	srv.Config.AllowGetAccessRequest = true
	return srv
}

func NewOAuthServer(
	authCodeAccessTokenExp, authCodeRefreshTokenExp int, authCodeGenerateRefresh bool,
	clientCredentialsAccessTokenExp, clientCredentialsRefreshTokenExp int, clientCredentialsGenerateRefresh bool,
	tokenStoreFilePath string, jwtAccessToken bool, jwtSecret string,
) *OAuthServer {
	clientStore := initClientStore()

	manager := initManager(clientStore,
		authCodeAccessTokenExp, authCodeRefreshTokenExp, authCodeGenerateRefresh,
		clientCredentialsAccessTokenExp, clientCredentialsRefreshTokenExp, clientCredentialsGenerateRefresh,
		tokenStoreFilePath, jwtAccessToken, jwtSecret,
	)

	srv := initServer(manager)
	srv.SetInternalErrorHandler(defaultInternalErrorHandler)
	srv.SetResponseErrorHandler(defaultResponseErrorHandler)
	srv.SetPasswordAuthorizationHandler(defaultPasswordAuthorizationHandler)
	srv.SetUserAuthorizationHandler(defaultUserAuthorizationHandler)
	return &OAuthServer{
		ClientStore: clientStore,
		Manager:     manager,
		Srv:         srv,
	}
}

func defaultInternalErrorHandler(err error) (re *errors.Response) {
	log.Println("Internal Error:", err.Error())
	return
}

func defaultResponseErrorHandler(re *errors.Response) {
	log.Println("Response Error:", re.Error.Error())
}

func defaultPasswordAuthorizationHandler(username, password string) (userID string, err error) {
	err = errors.New("username or password are not valid")
	return
}

func defaultUserAuthorizationHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	err = errors.New("username is not valid")
	return
}

// Password credentials
func (s *OAuthServer) SetPasswordAuthorizationHandler(handler server.PasswordAuthorizationHandler) {
	s.Srv.SetPasswordAuthorizationHandler(handler)
}

func (s *OAuthServer) SetUserAuthorizationHandler(handler server.UserAuthorizationHandler) {
	s.Srv.SetUserAuthorizationHandler(handler)
}

func (s *OAuthServer) SetInternalErrorHandler(handler server.InternalErrorHandler) {
	s.Srv.SetInternalErrorHandler(handler)
}

func (s *OAuthServer) SetResponseErrorHandler(handler server.ResponseErrorHandler) {
	s.Srv.SetResponseErrorHandler(handler)
}

func VerifyJWT(secret string, tokenStr string) (string, error) {
	// Parse and verify jwt access token
	token, err := jwt.ParseWithClaims(tokenStr, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("parse error")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(*generates.JWTAccessClaims)
	if !ok || !token.Valid {
		// panic("invalid token")
		return "", errors.New("invalid token")
	}

	fmt.Println("claims:", claims.Audience, claims.Id, claims.Subject)
	return claims.Audience, nil
}
