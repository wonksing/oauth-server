package repositories

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/mjwt"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/port"
)

type OAuthSelfRepo struct {
	oauthCookie port.OAuthCookie
	loginHtml   string
	allowHtml   string
}

func NewOAuthSelfRepo(oauthCookie port.OAuthCookie, loginHtml string, allowHtml string) port.AuthRepo {
	return &OAuthSelfRepo{
		oauthCookie: oauthCookie,
		loginHtml:   loginHtml,
		allowHtml:   allowHtml,
	}
}

func (repo *OAuthSelfRepo) SetReturnURI(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	repo.oauthCookie.WriteReturnURI(w, r.Form.Encode())

	return nil
}
func (repo *OAuthSelfRepo) SetRedirectURI(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}
	redirectURI := r.Form.Get("redirect_uri")
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
	w.Header().Set("Location", redirectURI)
	w.WriteHeader(http.StatusFound)
	return nil
}

func (repo *OAuthSelfRepo) SendToLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}
	// access token 지우기
	repo.oauthCookie.ClearAccessToken(w)
	repo.SetReturnURI(w, r)
	repo.SetRedirectURI(w, r)

	if !commons.FileExists(repo.loginHtml) {
		return errors.New("login html file does not exist")
	}
	commons.OutputHTML(w, r, repo.loginHtml)
	return nil
}

func (repo *OAuthSelfRepo) Authenticate(w http.ResponseWriter, r *http.Request, jwtSecret string, jwtExpiresSecond int64) error {
	// if userID != userPW {
	// 	return errors.New("user ID and password does not match")
	// }
	// return nil
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

func (repo *OAuthSelfRepo) SendToAllow(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	if !commons.FileExists(repo.allowHtml) {
		return errors.New("allow html file does not exist")
	}

	commons.OutputHTML(w, r, repo.allowHtml)
	// w.Header().Set("Location", repo.allowHtml)
	// w.WriteHeader(http.StatusFound)
	return nil
}

func (repo *OAuthSelfRepo) UserAuthorize(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	// Resource Owner가 허용했는지 확인한다
	// TODO Scope도 여기서 처리해야 한다(나중에...)
	allow := r.Form.Get("allow")
	if allow != "yes" {
		// 허용한 상태가 아닌 경우

		if allow == "no" {
			// 거절인 경우
			return moauth.ErrorUserDidNotAllow
		}

		// 허용하지도 거절하지도 않은 경우
		clientID := r.Form.Get("client_id")
		redirectURI := r.Form.Get("redirect_uri")
		if clientID != "" && redirectURI != "" {
			repo.oauthCookie.WriteRedirectURI(w, redirectURI)
			repo.oauthCookie.WriteReturnURI(w, r.Form.Encode())
			return moauth.ErrorUserNeedToAllow
		} else {
			repo.oauthCookie.ClearReturnURI(w)
			repo.oauthCookie.ClearRedirectURI(w)
			return errors.New("not authorized")
		}
	}

	returnURI, _ := repo.oauthCookie.ReadReturnURI(r)
	repo.oauthCookie.ClearReturnURI(w)
	repo.oauthCookie.ClearRedirectURI(w)
	// repo.oauthCookie.ClearAccessToken(w)

	if returnURI != "" {
		// oauth에 전달할 파라메터
		v, err := url.ParseQuery(returnURI)
		if err != nil {
			return err
		}
		r.Form = v
	}

	return nil
}
