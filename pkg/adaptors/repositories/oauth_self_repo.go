package repositories

import (
	"errors"
	"net/http"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/mjwt"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/port"
)

type OAuthSelfRepo struct {
	oauthCookie      port.OAuthCookie
	loginPageAPI     string
	authorizePageAPI string
}

func NewOAuthSelfRepo(oauthCookie port.OAuthCookie, loginPageAPI string, authorizePageAPI string) port.AuthRepo {
	return &OAuthSelfRepo{
		oauthCookie:      oauthCookie,
		loginPageAPI:     loginPageAPI,
		authorizePageAPI: authorizePageAPI,
	}
}

func (repo *OAuthSelfRepo) ClearAccessToken(w http.ResponseWriter) {
	repo.oauthCookie.ClearAccessToken(w)
}
func (repo *OAuthSelfRepo) SetReturnURI(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	if clientID != "" && redirectURI != "" {
		repo.oauthCookie.WriteReturnURI(w, r.Form.Encode())
	} else {
		repo.oauthCookie.ClearReturnURI(w)
		return errors.New("client id and redirect uri do not exist")
	}

	// repo.oauthCookie.WriteReturnURI(w, r.Form.Encode())

	return nil
}

func (repo *OAuthSelfRepo) GetReturnURI(r *http.Request) (string, error) {
	return repo.oauthCookie.ReadReturnURI(r)
}

func (repo *OAuthSelfRepo) ClearReturnURI(w http.ResponseWriter) {
	repo.oauthCookie.ClearReturnURI(w)
}

func (repo *OAuthSelfRepo) SetRedirectURI(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}
	redirectURI := r.Form.Get("redirect_uri")
	if redirectURI == "" {
		repo.oauthCookie.ClearRedirectURI(w)
		return errors.New("redirect uri does not exist")
	}
	repo.oauthCookie.WriteRedirectURI(w, redirectURI)

	return nil
}

func (repo *OAuthSelfRepo) GetRedirectURI(r *http.Request) (string, error) {
	return repo.oauthCookie.ReadRedirectURI(r)
}

func (repo *OAuthSelfRepo) ClearRedirectURI(w http.ResponseWriter) {
	repo.oauthCookie.ClearRedirectURI(w)
}

func (repo *OAuthSelfRepo) RedirectToClient(w http.ResponseWriter, r *http.Request) error {
	redirectURI, err := repo.oauthCookie.ReadRedirectURI(r)
	repo.oauthCookie.ClearRedirectURI(w)
	repo.oauthCookie.ClearReturnURI(w)

	if err != nil {
		return err
	}
	w.Header().Set("Location", redirectURI)
	w.WriteHeader(http.StatusFound)
	return nil
}

func (repo *OAuthSelfRepo) RedirectToLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	// access token 지우기
	repo.ClearAccessToken(w)
	repo.SetReturnURI(w, r)
	repo.SetRedirectURI(w, r)

	commons.Redirect(w, repo.loginPageAPI)
	return nil
}

func (repo *OAuthSelfRepo) Authenticate(w http.ResponseWriter, r *http.Request, jwtSecret string, jwtExpiresSecond int64) error {
	if r.Form == nil {
		r.ParseForm()
	}

	userID := r.Form.Get("username")
	userPW := r.Form.Get("password")
	if userID != userPW {
		return errors.New("user ID and password does not match")
	}

	returnURI, err := repo.oauthCookie.ReadReturnURI(r)
	if err != nil {
		return err
	}
	if returnURI == "" {
		return errors.New("return uri does not exist")
	}

	accessToken, err := mjwt.GenerateAccessToken(jwtSecret, userID, jwtExpiresSecond)
	if err != nil {
		return err
	}

	repo.oauthCookie.WriteAccessToken(w, accessToken)

	return nil
}

func (repo *OAuthSelfRepo) RedirectToAuthorize(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	commons.Redirect(w, repo.authorizePageAPI)
	return nil
}

func (repo *OAuthSelfRepo) AuthorizeAccess(w http.ResponseWriter, r *http.Request) string {
	if r.Form == nil {
		r.ParseForm()
	}

	allowStatus := r.Form.Get("allow_status")
	return allowStatus
	// ctx := moauth.WithAllowStatusContext(r.Context(), allowStatus)
	// r = r.WithContext(ctx)

	// return nil
}

func (repo *OAuthSelfRepo) CheckUserID(r *http.Request) (string, error) {
	if r.Form == nil {
		r.ParseForm()
	}
	return moauth.GetUserIDContext(r.Context())
}

func (repo *OAuthSelfRepo) CheckAuthorizeStatus(r *http.Request) (string, error) {
	// Resource Owner가 허용했는지 확인한다
	return moauth.GetAllowStatusContext(r.Context())

}
