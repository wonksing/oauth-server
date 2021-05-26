package uoauth

import (
	"net/http"

	"github.com/wonksing/oauth-server/pkg/port"
)

type Usecase interface {

	// SetReturnURI 사용자가 Code Authorization을 최초로 요청했을 때
	// 인증이 되어 있지 않다면 return uri를 쿠키에 저장한다.
	SetReturnURI(w http.ResponseWriter, r *http.Request) error
	SetRedirectURI(w http.ResponseWriter, r *http.Request) error

	// UserAuthorize 사용자가 인증되어 있는 상태에서 먼저 쿠키에 있는 return uri를 확인해 보고
	// 정보가 없다면 url parameter를 그대로 oauth 서버에 전달하여 authorization code를 사용자에게
	// 전달한다.
	UserAuthorize(w http.ResponseWriter, r *http.Request) error

	RedirectToClient(w http.ResponseWriter, r *http.Request) error

	// Login
	// 로그인 페이지로 보내기 전 쿠키 설정
	SendToLogin(w http.ResponseWriter, r *http.Request) error

	// Authenticate 사용자 인증
	// 사용자의 ID와 PW 검증, return uri 유무 확인 후 이상 없으면
	// access token을 생성하여 쿠키에 저장한다.
	Authenticate(w http.ResponseWriter, r *http.Request) error

	SendToAllow(w http.ResponseWriter, r *http.Request) error
}

type oauthUsecase struct {
	// Usecase

	jwtSecret        string
	jwtExpiresSecond int64
	authRepo         port.AuthRepo

	redirectURIAllow string
}

func NewOAuthUsecase(
	jwtSecret string,
	jwtExpiresSecond int64,
	authRepo port.AuthRepo,
	redirectURIAllow string,
) Usecase {
	return &oauthUsecase{
		jwtSecret:        jwtSecret,
		jwtExpiresSecond: jwtExpiresSecond,
		authRepo:         authRepo,
		redirectURIAllow: redirectURIAllow,
	}
}

func (u *oauthUsecase) SetReturnURI(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.SetReturnURI(w, r)
}
func (u *oauthUsecase) SetRedirectURI(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.SetRedirectURI(w, r)
}
func (u *oauthUsecase) UserAuthorize(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.UserAuthorize(w, r)
}

func (u *oauthUsecase) RedirectToClient(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.RedirectToClient(w, r)
}

func (u *oauthUsecase) SendToLogin(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.SendToLogin(w, r)
}

func (u *oauthUsecase) Authenticate(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.Authenticate(w, r, u.jwtSecret, u.jwtExpiresSecond)
}

func (u *oauthUsecase) SendToAllow(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.SendToAllow(w, r)
}
