package uoauth

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/wonksing/oauth-server/pkg/models/mjwt"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/port"
)

type Usecase interface {
	// ClearOAuthCookie 쿠키에 저장되어 있는 Oauth 관련 키값을 클리어한다.
	// moauth.KeyReturnURI, moauth.KeyAccessToken 등
	ClearOAuthCookie(w http.ResponseWriter)
	ClearOAuthUserCookie(w http.ResponseWriter)

	// SetReturnURI 사용자가 Code Authorization을 최초로 요청했을 때
	// 인증이 되어 있지 않다면 return uri를 쿠키에 저장한다.
	SetReturnURI(w http.ResponseWriter, r *http.Request) error
	SetRedirectURI(w http.ResponseWriter, r *http.Request) error

	// UserAuthorize 사용자가 인증이 되어 있는 상태에서 먼저 쿠키에 있는 return uri를 확인해 보고
	// 정보가 없다면 url parameter를 그대로 oauth 서버에 전달하여 authorization code를 사용자에게
	// 전달한다.
	UserAuthorize(w http.ResponseWriter, r *http.Request) error

	RedirectToAllowPage(w http.ResponseWriter, r *http.Request)
	RedirectToClient(w http.ResponseWriter, r *http.Request)

	// PreAuthenticate
	// 로그인 페이지로 보내기 전 쿠키 설정
	PreAuthenticate(w http.ResponseWriter, r *http.Request) error

	// Authenticate 사용자 인증
	// 사용자의 ID와 PW 검증, return uri 유무 확인 후 이상 없으면
	// access token을 생성하여 쿠키에 저장한다.
	Authenticate(w http.ResponseWriter, r *http.Request) error
}

type oauthUsecase struct {
	// Usecase

	jwtSecret        string
	jwtExpiresSecond int64
	oauthCookie      port.OAuthCookie
	authRepo         port.AuthRepo

	redirectURIAllow string
}

func NewOAuthUsecase(
	jwtSecret string,
	jwtExpiresSecond int64,
	oauthCookie port.OAuthCookie,
	authRepo port.AuthRepo,
	redirectURIAllow string,
) Usecase {
	return &oauthUsecase{
		jwtSecret:        jwtSecret,
		jwtExpiresSecond: jwtExpiresSecond,
		oauthCookie:      oauthCookie,
		authRepo:         authRepo,
		redirectURIAllow: redirectURIAllow,
	}
}

func (u *oauthUsecase) ClearOAuthCookie(w http.ResponseWriter) {
	// u.oauthCookie.ClearAccessToken(w)
	u.oauthCookie.ClearReturnURI(w)
	u.oauthCookie.ClearRedirectURI(w)
}
func (u *oauthUsecase) ClearOAuthUserCookie(w http.ResponseWriter) {
	u.oauthCookie.ClearAccessToken(w)
}

func (u *oauthUsecase) SetReturnURI(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	u.oauthCookie.WriteReturnURI(w, r.Form.Encode())
	// u.oauthCookie.ClearAccessToken(w)

	return nil
}
func (u *oauthUsecase) SetRedirectURI(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}
	redirectURI := r.Form.Get("redirect_uri")
	u.oauthCookie.WriteRedirectURI(w, redirectURI)

	return nil
}
func (u *oauthUsecase) UserAuthorize(w http.ResponseWriter, r *http.Request) error {

	if r.Form == nil {
		r.ParseForm()
	}

	allow := r.Form.Get("allow")

	if allow != "yes" {
		if allow == "no" {
			return moauth.ErrorUserDidNotAllow
		}
		clientID := r.Form.Get("client_id")
		redirectURI := r.Form.Get("redirect_uri")
		if clientID != "" && redirectURI != "" {
			u.SetReturnURI(w, r)
			return moauth.ErrorUserNeedToAllow
		} else {
			u.ClearOAuthCookie(w)
			return errors.New("not authorized")
		}
	}

	returnURI, _ := u.oauthCookie.ReadReturnURI(r)
	u.oauthCookie.ClearReturnURI(w)

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

func (u *oauthUsecase) RedirectToAllowPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", u.redirectURIAllow)
	w.WriteHeader(http.StatusFound)
}

func (u *oauthUsecase) RedirectToClient(w http.ResponseWriter, r *http.Request) {
	redirectURI, err := u.oauthCookie.ReadRedirectURI(r)
	u.ClearOAuthCookie(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Location", redirectURI)
	w.WriteHeader(http.StatusFound)
}

func (u *oauthUsecase) PreAuthenticate(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	// access token 지우기
	u.ClearOAuthUserCookie(w)

	return nil
}

func (u *oauthUsecase) Authenticate(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	userID := r.Form.Get("username")
	userPW := r.Form.Get("password")
	err := u.authRepo.Authenticate(userID, userPW)
	if err != nil {
		return err
	}

	returnURI, err := u.oauthCookie.ReadReturnURI(r)
	if err != nil {
		return err
	}
	if returnURI == "" {
		return errors.New("return uri does not exist")
	}

	accessToken, err := mjwt.GenerateAccessToken(u.jwtSecret, userID, u.jwtExpiresSecond)
	if err != nil {
		return err
	}

	u.oauthCookie.WriteAccessToken(w, accessToken)

	// TODO 불필요
	// u.oauthCookie.WriteReturnURI(w, returnURI)

	return nil
}
