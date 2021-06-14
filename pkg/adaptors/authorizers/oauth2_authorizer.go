package authorizers

import (
	"context"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/dgrijalva/jwt-go"
	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/mjwt"
	"github.com/wonksing/oauth-server/pkg/models/moauth"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

// type oauth2Server struct {
// 	oauthServer *commons.OAuthServer
// }

// func NewOAuth2Server(oauthServer *commons.OAuthServer) port.OAuth2Server {

// 	return &oauth2Server{
// 		oauthServer: oauthServer,
// 	}
// }

func (a *oauth2Server) AuthorizeCode(w http.ResponseWriter, r *http.Request) error {
	return a.Srv.HandleAuthorizeRequest(w, r)
}

func (a *oauth2Server) Token(w http.ResponseWriter, r *http.Request) error {
	return a.Srv.HandleTokenRequest(w, r)
}

func (a *oauth2Server) ValidateToken(r *http.Request) (accessToken string, expiresIn int64, clientID string, userID string, scope string, err error) {
	token, err := a.Srv.ValidationBearerToken(r)
	if err != nil {
		return
	}
	accessToken = token.GetAccess()
	t := token.GetAccessCreateAt().Add(token.GetAccessExpiresIn())
	expiresIn = int64(time.Until(t).Seconds())
	clientID = token.GetClientID()
	userID = token.GetUserID()
	scope = token.GetScope()
	return
}

func (a *oauth2Server) AddClient(clientID, clientSecret, clientDomain, scope string) error {
	err := a.ClientStore.Set(clientID, &moauth.OAuthClient{
		ID:     clientID,
		Secret: clientSecret,
		Domain: clientDomain,
		Scope:  scope,
	})
	if err != nil {
		return err
	}

	return nil
}

func (a *oauth2Server) GetClientByID(clientID string) (*moauth.OAuthClient, error) {
	ci, err := a.ClientStore.GetByID(context.Background(), clientID)
	if err != nil {
		return nil, err
	}

	oci := ci.(*moauth.OAuthClient)
	return oci, nil
}

//////////////////

type oauth2Server struct {
	ClientStore *store.ClientStore
	Manager     *manage.Manager
	Srv         *server.Server
}

func NewOAuth2Server(
	authCodeAccessTokenExp, authCodeRefreshTokenExp int, authCodeGenerateRefresh bool,
	clientCredentialsAccessTokenExp, clientCredentialsRefreshTokenExp int, clientCredentialsGenerateRefresh bool,
	tokenStoreFilePath string, jwtAccessToken bool, jwtSecret string,
	allowedGrantType []oauth2.GrantType,
	clientCredentials moauth.OAuthClientList,
) *oauth2Server {
	clientStore := initClientStore(clientCredentials)

	manager := initManager(clientStore,
		authCodeAccessTokenExp, authCodeRefreshTokenExp, authCodeGenerateRefresh,
		clientCredentialsAccessTokenExp, clientCredentialsRefreshTokenExp, clientCredentialsGenerateRefresh,
		tokenStoreFilePath, jwtAccessToken, jwtSecret,
	)

	srv := initServer(manager, allowedGrantType)
	srv.SetInternalErrorHandler(defaultInternalErrorHandler)
	srv.SetResponseErrorHandler(defaultResponseErrorHandler)
	srv.SetPasswordAuthorizationHandler(defaultPasswordAuthorizationHandler)
	srv.SetUserAuthorizationHandler(defaultUserAuthorizationHandler)
	return &oauth2Server{
		ClientStore: clientStore,
		Manager:     manager,
		Srv:         srv,
	}
}

func initClientStore(clientCredentials moauth.OAuthClientList) *store.ClientStore {
	cs := store.NewClientStore()
	for _, val := range clientCredentials {
		cs.Set(val.ID, val)
	}
	return cs
}
func initManager(clientStore *store.ClientStore,
	authCodeAccessTokenExp, authCodeRefreshTokenExp int, authCodeGenerateRefresh bool,
	clientCredentialsAccessTokenExp, clientCredentialsRefreshTokenExp int, clientCredentialsGenerateRefresh bool,
	tokenStoreFilePath string, jwtAccessToken bool, jwtSecret string,
) *manage.Manager {

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
		// manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte(jwtSecret), jwt.SigningMethodHS512))
		manager.MapAccessGenerate(mjwt.NewJWTAccessGenerate("", []byte(jwtSecret), jwt.SigningMethodHS512))
	} else {
		manager.MapAccessGenerate(generates.NewAccessGenerate())
	}

	manager.MapClientStorage(clientStore)

	return manager
}

func initServer(manager *manage.Manager, allowedGrantType []oauth2.GrantType) *server.Server {
	srv := server.NewDefaultServer(manager)
	srv.Config.AllowGetAccessRequest = true
	// srv.SetAllowedGrantType(oauth2.AuthorizationCode, oauth2.ClientCredentials, oauth2.PasswordCredentials)
	srv.SetAllowedGrantType(allowedGrantType...)
	return srv
}

func defaultInternalErrorHandler(err error) (re *errors.Response) {
	log.Println("Internal Error:", err.Error())
	return
}

func defaultResponseErrorHandler(re *errors.Response) {
	// 오류 응답은 다음과 같은 json 포맷으로 통일하도록 하자
	// {"error":"unauthorized_client","error_description":"The client is not authorized to request an authorization code using this method"}
	log.WithFields(commons.LogrusFields()).Error(re.Error)
}

func defaultPasswordAuthorizationHandler(username, password string) (userID string, err error) {
	err = errors.New("username or password are not valid")
	return
}

func defaultUserAuthorizationHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	err = errors.New("username is not valid")
	return
}
