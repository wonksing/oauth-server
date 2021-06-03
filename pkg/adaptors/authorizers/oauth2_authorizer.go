package authorizers

import (
	"context"
	"net/http"
	"time"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/port"
)

type oauth2Authorizer struct {
	oauthServer *commons.OAuthServer
}

func NewOAuth2Authorizer(oauthServer *commons.OAuthServer) port.OAuth2Authorizer {

	return &oauth2Authorizer{
		oauthServer: oauthServer,
	}
}

func (a *oauth2Authorizer) AuthorizeCode(w http.ResponseWriter, r *http.Request) error {
	return a.oauthServer.Srv.HandleAuthorizeRequest(w, r)
}

func (a *oauth2Authorizer) Token(w http.ResponseWriter, r *http.Request) error {
	return a.oauthServer.Srv.HandleTokenRequest(w, r)
}

func (a *oauth2Authorizer) ValidateToken(r *http.Request) (accessToken string, expiresIn int64, clientID string, userID string, scope string, err error) {
	token, err := a.oauthServer.Srv.ValidationBearerToken(r)
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

func (a *oauth2Authorizer) AddClient(clientID, clientSecret, clientDomain, scope string) error {
	err := a.oauthServer.ClientStore.Set(clientID, &moauth.OAuthClient{
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

func (a *oauth2Authorizer) GetClientByID(clientID string) (*moauth.OAuthClient, error) {
	ci, err := a.oauthServer.ClientStore.GetByID(context.Background(), clientID)
	if err != nil {
		return nil, err
	}

	oci := ci.(*moauth.OAuthClient)
	return oci, nil
}
