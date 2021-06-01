package repositories

import (
	"errors"
	"net/http"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/merror"
	"github.com/wonksing/oauth-server/pkg/models/mjwt"
	"github.com/wonksing/oauth-server/pkg/port"
)

type OAuthSelfRepo struct {
	oauthCookie      port.OAuthCookie
	jwtSecret        string
	loginPageAPI     string
	authorizePageAPI string
}

func NewOAuthSelfRepo(oauthCookie port.OAuthCookie, jwtSecret string, loginPageAPI string, authorizePageAPI string) port.AuthRepo {
	return &OAuthSelfRepo{
		oauthCookie:      oauthCookie,
		jwtSecret:        jwtSecret,
		loginPageAPI:     loginPageAPI,
		authorizePageAPI: authorizePageAPI,
	}
}

func (repo *OAuthSelfRepo) SetClientReturnURI(w http.ResponseWriter, r *http.Request) error {
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	if clientID != "" && redirectURI != "" {
		repo.oauthCookie.WriteReturnURI(w, r.Form.Encode())
	} else {
		repo.oauthCookie.ClearReturnURI(w)
		return errors.New("client id and redirect uri do not exist")
	}

	return nil
}

func (repo *OAuthSelfRepo) SetClientRedirectURI(w http.ResponseWriter, r *http.Request) error {
	redirectURI := r.Form.Get("redirect_uri")
	if redirectURI == "" {
		repo.oauthCookie.ClearRedirectURI(w)
		return errors.New("redirect uri does not exist")
	}
	repo.oauthCookie.WriteRedirectURI(w, redirectURI)

	return nil
}

func (repo *OAuthSelfRepo) RedirectToClient(w http.ResponseWriter, r *http.Request) error {

	redirectURI, err := repo.oauthCookie.ReadRedirectURI(r)
	repo.oauthCookie.ClearRedirectURI(w)
	repo.oauthCookie.ClearReturnURI(w)

	if err != nil {
		return err
	}

	if redirectURI == "" {
		return errors.New("no client to redirect")
	}

	commons.Redirect(w, redirectURI)
	return nil
}

func (repo *OAuthSelfRepo) GetUserID(r *http.Request) (string, error) {
	token, err := repo.oauthCookie.ReadAccessToken(r)
	if err != nil {
		return "", merror.ErrorUserIDNotFound
	}
	claim, _, err := mjwt.ValidateAccessToken(token, repo.jwtSecret)
	if err != nil {
		return "", merror.ErrorUserIDNotFound
	}
	return claim.UsrID, nil
}

func (repo *OAuthSelfRepo) GetAuthStatus(r *http.Request) (string, error) {
	status := r.Form.Get("allow_status")
	if status == "" {
		return "", merror.ErrorUserNeedToAllow
	}
	if status != "yes" {
		return "", merror.ErrorUserDidNotAllow
	}

	return status, nil
}

func (repo *OAuthSelfRepo) GetReturnURI(r *http.Request) (string, error) {

	return repo.oauthCookie.ReadReturnURI(r)

}

func (repo *OAuthSelfRepo) RedirectToLogin(w http.ResponseWriter, r *http.Request) error {
	repo.oauthCookie.ClearAccessToken(w)
	uri := repo.loginPageAPI

	commons.Redirect(w, uri)
	return nil
}

func (repo *OAuthSelfRepo) RedirectToAuthorize(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	commons.Redirect(w, repo.authorizePageAPI)
	return nil
}
