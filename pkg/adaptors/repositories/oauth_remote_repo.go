package repositories

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/merror"
	"github.com/wonksing/oauth-server/pkg/models/mjwt"
	"github.com/wonksing/oauth-server/pkg/port"
)

type OAuthRemoteRepo struct {
	oauthCookie      port.OAuthCookie
	jwtSecret        string
	jwtExpiresSecond int64
	loginPageAPI     string
	authorizePageAPI string
	redirectURI      string // 원격지에서 이 인증서버로 돌아올 URI
}

func NewOAuthRemoteRepo(oauthCookie port.OAuthCookie, jwtSecret string, jwtExpiresSecond int64, loginPageAPI string, authorizePageAPI string, redirectURI string) port.AuthRepo {
	return &OAuthRemoteRepo{
		oauthCookie:      oauthCookie,
		jwtSecret:        jwtSecret,
		jwtExpiresSecond: jwtExpiresSecond,
		loginPageAPI:     loginPageAPI,
		authorizePageAPI: authorizePageAPI,
		redirectURI:      redirectURI,
	}
}

func (repo *OAuthRemoteRepo) ClearClientReturnURI(w http.ResponseWriter) {
	repo.oauthCookie.ClearReturnURI(w)
}

func (repo *OAuthRemoteRepo) SetClientReturnURI(w http.ResponseWriter, r *http.Request) error {
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	if clientID != "" && redirectURI != "" {
		repo.oauthCookie.WriteReturnURI(w, r.Form.Encode())
	} else {
		repo.oauthCookie.ClearReturnURI(w)
		if clientID == "" {
			return merror.ErrorNoClientID
		}
		if redirectURI == "" {
			return merror.ErrorNoRedirectURI
		}

		return merror.ErrorInsufficientClientInfo
	}

	return nil
}

func (repo *OAuthRemoteRepo) ClearClientRedirectURI(w http.ResponseWriter) {
	repo.oauthCookie.ClearRedirectURI(w)
}

func (repo *OAuthRemoteRepo) SetClientRedirectURI(w http.ResponseWriter, r *http.Request) error {
	redirectURI := r.Form.Get("redirect_uri")
	if redirectURI == "" {
		repo.oauthCookie.ClearRedirectURI(w)
		return merror.ErrorNoRedirectURI
	}
	repo.oauthCookie.WriteRedirectURI(w, redirectURI)

	return nil
}

func (repo *OAuthRemoteRepo) RedirectToClient(w http.ResponseWriter, r *http.Request) error {

	redirectURI, err := repo.oauthCookie.ReadRedirectURI(r)
	repo.oauthCookie.ClearRedirectURI(w)
	repo.oauthCookie.ClearReturnURI(w)

	if err != nil {
		return err
	}

	if redirectURI == "" {
		return merror.ErrorNoRedirectURI
	}

	commons.Redirect(w, redirectURI)
	return nil
}

func (repo *OAuthRemoteRepo) SetAccessToken(w http.ResponseWriter, accessToken string) {
	repo.oauthCookie.WriteAccessToken(w, accessToken)
}

func (repo *OAuthRemoteRepo) ClearAccessToken(w http.ResponseWriter) {
	repo.oauthCookie.ClearAccessToken(w)
}

func (repo *OAuthRemoteRepo) GetUserID(r *http.Request) (string, error) {
	userID := r.Form.Get("user_id")
	if userID == "" {
		return "", merror.ErrorUserIDNotFound
	}
	return userID, nil
}

func (repo *OAuthRemoteRepo) GetAuthStatus(r *http.Request) (string, error) {
	status := r.Form.Get("allow_status")
	if status == "" {
		return "", merror.ErrorUserNeedToAllow
	}
	if status != "yes" {
		return "", merror.ErrorUserDidNotAllow
	}

	return status, nil
}

func (repo *OAuthRemoteRepo) GetReturnURI(r *http.Request) (string, error) {

	token := r.Form.Get("token")
	claim, _, err := mjwt.ValidateAccessToken(token, repo.jwtSecret)
	if err != nil {
		return "", merror.ErrorNoReturnURI
	}
	if claim.ReturnURI == "" {
		return "", merror.ErrorNoReturnURI
	}
	r.Form, err = url.ParseQuery(claim.ReturnURI)
	if err != nil {
		return "", merror.ErrorNoReturnURI
	}
	// repo.oauthCookie.WriteReturnURI(w, r.Form.Encode())
	// return repo.oauthCookie.ReadReturnURI(r)
	return r.Form.Encode(), nil
}

func (repo *OAuthRemoteRepo) RedirectToLogin(w http.ResponseWriter, r *http.Request) error {
	repo.oauthCookie.ClearAccessToken(w)

	urlVal := r.Form.Encode()
	expireTimeUnix := time.Now().Add(time.Duration(repo.jwtExpiresSecond) * time.Second).Unix()
	token, err := mjwt.GenerateAccessToken(repo.jwtSecret, "", expireTimeUnix, urlVal)
	if err != nil {
		return err
	}
	redirectURI := repo.redirectURI + "?token=" + token

	uri := repo.loginPageAPI

	var buf bytes.Buffer
	buf.WriteString(uri)
	v := url.Values{}
	v.Set("redirect_uri", redirectURI)

	if strings.Contains(uri, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	uri = buf.String()

	commons.Redirect(w, uri)
	return nil
}

func (repo *OAuthRemoteRepo) RedirectToAuthorize(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	commons.Redirect(w, repo.authorizePageAPI)
	return nil
}
