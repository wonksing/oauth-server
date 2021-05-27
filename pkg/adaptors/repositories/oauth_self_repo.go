package repositories

import (
	"errors"
	"net/http"

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

func (repo *OAuthSelfRepo) Login(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	// access token 지우기
	repo.oauthCookie.ClearAccessToken(w)
	repo.SetReturnURI(w, r)
	repo.SetRedirectURI(w, r)

	w.Header().Set("Location", repo.loginPageAPI)
	w.WriteHeader(http.StatusFound)
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

func (repo *OAuthSelfRepo) Access(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	w.Header().Set("Location", repo.authorizePageAPI)
	w.WriteHeader(http.StatusFound)
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

// func (repo *OAuthSelfRepo) UserAuthorize(w http.ResponseWriter, r *http.Request) error {
// 	if r.Form == nil {
// 		r.ParseForm()
// 	}

// 	// // Resource Owner가 허용했는지 확인한다
// 	// // TODO Scope도 여기서 처리해야 한다(나중에...)
// 	// _, err := moauth.GetAllowStatus(r.Context())
// 	// if err != nil {
// 	// 	fmt.Println(err)
// 	// 	if err == moauth.ErrorUserNeedToAllow {
// 	// 		// 허용하지도 거절하지도 않은 경우
// 	// 		clientID := r.Form.Get("client_id")
// 	// 		redirectURI := r.Form.Get("redirect_uri")
// 	// 		if clientID != "" && redirectURI != "" {
// 	// 			repo.oauthCookie.WriteRedirectURI(w, redirectURI)
// 	// 			repo.oauthCookie.WriteReturnURI(w, r.Form.Encode())
// 	// 			return moauth.ErrorUserNeedToAllow
// 	// 		} else {
// 	// 			repo.oauthCookie.ClearReturnURI(w)
// 	// 			repo.oauthCookie.ClearRedirectURI(w)
// 	// 			return errors.New("not authorized")
// 	// 		}
// 	// 	}
// 	// 	return err
// 	// }

// 	returnURI, _ := repo.oauthCookie.ReadReturnURI(r)
// 	repo.oauthCookie.ClearReturnURI(w)
// 	repo.oauthCookie.ClearRedirectURI(w)
// 	// repo.oauthCookie.ClearAccessToken(w)

// 	if returnURI != "" {
// 		// oauth에 전달할 파라메터
// 		v, err := url.ParseQuery(returnURI)
// 		if err != nil {
// 			return err
// 		}
// 		r.Form = v
// 	}

// 	return nil
// }

func (repo *OAuthSelfRepo) CheckUserID(r *http.Request) (string, error) {
	if r.Form == nil {
		r.ParseForm()
	}
	return moauth.GetUserIDContext(r.Context())
}

func (repo *OAuthSelfRepo) CheckAuthorizeStatus(r *http.Request) (string, error) {
	// Resource Owner가 허용했는지 확인한다
	// TODO Scope도 여기서 처리해야 한다(나중에...)
	return moauth.GetAllowStatus(r.Context())

	// if err != nil {
	// 	if err == moauth.ErrorUserNeedToAllow {
	// 		// 허용하지도 거절하지도 않은 경우
	// 		clientID := r.Form.Get("client_id")
	// 		redirectURI := r.Form.Get("redirect_uri")
	// 		if clientID != "" && redirectURI != "" {
	// 			repo.oauthCookie.WriteRedirectURI(w, redirectURI)
	// 			repo.oauthCookie.WriteReturnURI(w, r.Form.Encode())
	// 			return "", moauth.ErrorUserNeedToAllow
	// 		} else {
	// 			repo.oauthCookie.ClearReturnURI(w)
	// 			repo.oauthCookie.ClearRedirectURI(w)
	// 			return "", errors.New("not authorized")
	// 		}
	// 	}
	// 	return "", err
	// }
	// return status, nil
}
