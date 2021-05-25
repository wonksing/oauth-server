package uoauth

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/wonksing/oauth-server/pkg/models/mjwt"
	"github.com/wonksing/oauth-server/pkg/port"
)

const (
	KeyReturnURI   = "oauth_return_uri"
	KeyAccessToken = "access_token"
)

type Usecase interface {
	BeforeUserAuthorize(w http.ResponseWriter, r *http.Request) error

	BeforeAuthenticate(w http.ResponseWriter, r *http.Request) error
	Authenticate(userID, userPW string) error
	AfterAuthenticate(w http.ResponseWriter, r *http.Request, userID string) error
}

type oauthUsecase struct {
	// Usecase

	jwtSecret   string
	oauthCookie port.OAuthCookie
	authRepo    port.AuthRepo
}

func NewOAuthUsecase(jwtSecret string, oauthCookie port.OAuthCookie, authRepo port.AuthRepo) Usecase {
	return &oauthUsecase{
		jwtSecret:   jwtSecret,
		oauthCookie: oauthCookie,
		authRepo:    authRepo,
	}
}

func (u *oauthUsecase) BeforeUserAuthorize(w http.ResponseWriter, r *http.Request) error {
	// return_uri가 있는지 확인
	returnURI, _ := u.oauthCookie.ReadReturnURI(r)
	u.oauthCookie.ClearReturnURI(w)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }
	// if c1 == nil {
	// 	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	// 	return
	// }
	if returnURI != "" {
		// oauth에 전달
		v, err := url.ParseQuery(returnURI)
		if err != nil {
			return err
		}
		r.Form = v
	}

	return nil
}

func (u *oauthUsecase) BeforeAuthenticate(w http.ResponseWriter, r *http.Request) error {
	returnURI, err := u.oauthCookie.ReadReturnURI(r)
	if err != nil {
		return err
	}

	u.oauthCookie.ClearAccessToken(w)
	u.oauthCookie.WriteReturnURI(w, returnURI)

	return nil
}

func (u *oauthUsecase) Authenticate(userID, userPW string) error {
	return u.authRepo.Authenticate(userID, userPW)
}

func (u *oauthUsecase) AfterAuthenticate(w http.ResponseWriter, r *http.Request, userID string) error {
	returnURI, err := u.oauthCookie.ReadReturnURI(r)
	if err != nil {
		return err
	}
	if returnURI == "" {
		return errors.New("return uri does not exist")
	}

	accessToken, err := mjwt.GenerateAccessToken(u.jwtSecret, userID)
	if err != nil {
		return err
	}

	u.oauthCookie.WriteAccessToken(w, accessToken)
	u.oauthCookie.WriteReturnURI(w, returnURI)

	return nil
}
