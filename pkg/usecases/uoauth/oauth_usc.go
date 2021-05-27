package uoauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/port"
)

type Usecase interface {

	// SetReturnURI 사용자가 Code Authorization을 최초로 요청했을 때
	// 인증이 되어 있지 않다면 return uri를 쿠키에 저장한다.
	SetReturnURI(w http.ResponseWriter, r *http.Request) error
	SetRedirectURI(w http.ResponseWriter, r *http.Request) error

	RedirectToClient(w http.ResponseWriter, r *http.Request) error

	// Login
	// 로그인 페이지로 보내기 전 쿠키 설정
	Login(w http.ResponseWriter, r *http.Request) error

	// Authenticate 사용자 인증
	// 사용자의 ID와 PW 검증, return uri 유무 확인 후 이상 없으면
	// access token을 생성하여 쿠키에 저장한다.
	Authenticate(w http.ResponseWriter, r *http.Request) error

	Access(w http.ResponseWriter, r *http.Request) error
	AuthorizeAccess(w http.ResponseWriter, r *http.Request) (context.Context, error)

	// UserAuthorize 사용자가 인증되어 있는 상태에서 먼저 쿠키에 있는 return uri를 확인해 보고
	// 정보가 없다면 url parameter를 그대로 oauth 서버에 전달하여 authorization code를 사용자에게
	// 전달한다.
	GrantAuthorizeCode(w http.ResponseWriter, r *http.Request) error
}

type oauthUsecase struct {
	oauthServer      *commons.OAuthServer
	jwtSecret        string
	jwtExpiresSecond int64
	authRepo         port.AuthRepo
}

func NewOAuthUsecase(
	oauthServer *commons.OAuthServer,
	jwtSecret string,
	jwtExpiresSecond int64,
	authRepo port.AuthRepo,
) Usecase {
	return &oauthUsecase{
		oauthServer:      oauthServer,
		jwtSecret:        jwtSecret,
		jwtExpiresSecond: jwtExpiresSecond,
		authRepo:         authRepo,
	}
}

func (u *oauthUsecase) SetReturnURI(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.SetReturnURI(w, r)
}
func (u *oauthUsecase) SetRedirectURI(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.SetRedirectURI(w, r)
}

func (u *oauthUsecase) RedirectToClient(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.RedirectToClient(w, r)
}

func (u *oauthUsecase) Login(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.Login(w, r)
}

func (u *oauthUsecase) Authenticate(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.Authenticate(w, r, u.jwtSecret, u.jwtExpiresSecond)
}

func (u *oauthUsecase) Access(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.Access(w, r)
}

func (u *oauthUsecase) AuthorizeAccess(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	status := u.authRepo.AuthorizeAccess(w, r)
	if status == "" {
		return context.Background(), u.Access(w, r)
		// return r, moauth.ErrorUserNeedToAllow
	}
	if status != "yes" {
		return context.Background(), u.RedirectToClient(w, r)
		// return r, moauth.ErrorUserDidNotAllow
	}

	ctx := moauth.WithAllowStatusContext(r.Context(), status)

	return ctx, nil
}

func (u *oauthUsecase) GrantAuthorizeCode(w http.ResponseWriter, r *http.Request) error {
	userID, err := u.authRepo.CheckUserID(r)
	if err != nil {
		if err == moauth.ErrorUserIDNotFound {
			return u.Login(w, r)
		}
		return err
	}
	fmt.Println(userID)

	status, err := u.authRepo.CheckAuthorizeStatus(r)
	if err != nil {
		if err == moauth.ErrorUserNeedToAllow {
			// 허용하지도 거절하지도 않은 경우
			err = u.authRepo.SetReturnURI(w, r)
			if err != nil {
				return err
			}
			err = u.authRepo.SetRedirectURI(w, r)
			if err != nil {
				return err
			}
			return u.Access(w, r)

		} else if err == moauth.ErrorUserDidNotAllow {
			return u.authRepo.RedirectToClient(w, r)
		}
		return err
	}
	fmt.Println(status)

	returnURI, err := u.authRepo.GetReturnURI(r)
	if err != nil {
		return err
	}
	u.authRepo.ClearReturnURI(w)
	if returnURI != "" {
		// oauth에 전달할 파라메터
		v, err := url.ParseQuery(returnURI)
		if err != nil {
			return err
		}
		r.Form = v
	}

	// err = u.authRepo.UserAuthorize(w, r)
	// if err != nil {
	// 	if err == moauth.ErrorUserDidNotAllow {
	// 		return u.RedirectToClient(w, r)
	// 	} else if err == moauth.ErrorUserNeedToAllow {
	// 		return u.Access(w, r)
	// 	} else if err == moauth.ErrorUserIDNotFound {
	// 		return u.Login(w, r)
	// 	}
	// 	return err
	// }

	// h.oauthUsc.ClearOAuthCookie(w)

	return u.oauthServer.Srv.HandleAuthorizeRequest(w, r)
}
