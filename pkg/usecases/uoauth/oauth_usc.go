package uoauth

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-oauth2/oauth2/models"
	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/merror"
	"github.com/wonksing/oauth-server/pkg/models/mjwt"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/port"
)

// Usecase OAuth input port
type Usecase interface {

	// SetClientReturnURI 사용자가 Code Authorization 요청 직후
	// 인증이 되어 있지 않다면 return uri를 쿠키에 저장한다.
	SetClientReturnURI(w http.ResponseWriter, r *http.Request) error

	// SetClientRedirectURI 인가를 거부했을 때 돌려보내줄 URI
	SetClientRedirectURI(w http.ResponseWriter, r *http.Request) error

	// RedirectToClient Client에게 돌려보내기(인가 거부시)
	RedirectToClient(w http.ResponseWriter, r *http.Request) error

	// RedirectToLogin 로그인 페이지로 보낸다
	RedirectToLogin(w http.ResponseWriter, r *http.Request) error

	// Authenticate 사용자 인증
	// 사용자의 ID와 PW 검사, return uri 유무 확인 후 이상 없으면
	// access token을 생성하여 쿠키에 저장하고 인가 페이지로 보낸다.
	Authenticate(w http.ResponseWriter, r *http.Request) error

	// RedirectToAuthorize 접근인가 페이지로 보낸다
	RedirectToAuthorize(w http.ResponseWriter, r *http.Request) error

	// GrantAuthorizeCode Authorization Code를 발급하여 클라이언트에 전달한다.
	// 사용자 인증과 인가 확인 후 발급한다.
	GrantAuthorizeCode(w http.ResponseWriter, r *http.Request) error

	// RequestToken AccessToken을 발급해준다
	RequestToken(w http.ResponseWriter, r *http.Request) error

	// VerifyToken 토큰을 검증한다.
	VerifyToken(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error)

	// AddClientCredential 새로운 클라이언트를 추가한다.
	AddClientCredential(clientID, clientSecret, clientDomain string) (map[string]interface{}, error)

	// views
	// Login 페이지
	Login(w http.ResponseWriter, r *http.Request) error
	// Authorize 페이지, 클라이언트에게 접근을 인가하는 페이지
	Authorize(w http.ResponseWriter, r *http.Request) error
}

type oauthUsecase struct {
	oauthServer      *commons.OAuthServer
	jwtSecret        string
	jwtExpiresSecond int64
	oauthCookie      port.OAuthCookie
	authRepo         port.AuthRepo
	authView         port.AuthView
	resRepo          port.ResourceRepo
}

func NewOAuthUsecase(
	oauthServer *commons.OAuthServer,
	jwtSecret string,
	jwtExpiresSecond int64,
	oauthCookie port.OAuthCookie,
	authRepo port.AuthRepo,
	authView port.AuthView,
	resRepo port.ResourceRepo,
) Usecase {

	usc := &oauthUsecase{
		oauthServer:      oauthServer,
		jwtSecret:        jwtSecret,
		jwtExpiresSecond: jwtExpiresSecond,
		oauthCookie:      oauthCookie,
		authRepo:         authRepo,
		authView:         authView,
		resRepo:          resRepo,
	}
	return usc
}

func (u *oauthUsecase) SetClientReturnURI(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}
	return u.authRepo.SetClientReturnURI(w, r)
}
func (u *oauthUsecase) SetClientRedirectURI(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}
	return u.authRepo.SetClientRedirectURI(w, r)
}

func (u *oauthUsecase) RedirectToClient(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.RedirectToClient(w, r)
}

func (u *oauthUsecase) RedirectToLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	err := u.SetClientReturnURI(w, r)
	if err != nil {
		return err
	}
	err = u.SetClientRedirectURI(w, r)
	if err != nil {
		return err
	}

	return u.authRepo.RedirectToLogin(w, r)
}

func (u *oauthUsecase) Authenticate(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	userID := r.Form.Get("username")
	userPW := r.Form.Get("password")
	err := u.resRepo.Authenticate(userID, userPW)
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
	return nil
}

func (u *oauthUsecase) RedirectToAuthorize(w http.ResponseWriter, r *http.Request) error {
	return u.authRepo.RedirectToAuthorize(w, r)

}

func (u *oauthUsecase) GrantAuthorizeCode(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	userID, err := u.authRepo.GetUserID(r)
	if err != nil {
		if err == merror.ErrorUserIDNotFound {
			return u.RedirectToLogin(w, r)
		}
		return err
	}

	_, err = u.authRepo.GetAuthStatus(r)
	if err != nil {
		if err == merror.ErrorUserNeedToAllow {
			// 허용하지도 거절하지도 않은 경우
			err = u.SetClientReturnURI(w, r)
			if err != nil {
				return err
			}
			err = u.SetClientRedirectURI(w, r)
			if err != nil {
				return err
			}
			return u.RedirectToAuthorize(w, r)

		} else if err == merror.ErrorUserDidNotAllow {
			return u.RedirectToClient(w, r)
		}
		return err
	}

	returnURI, err := u.authRepo.GetReturnURI(r)
	if err != nil {
		return err
	}
	if returnURI != "" {
		// oauth에 전달할 파라메터 다시 붙여주기(client_id, redirect_uri 등)
		v, err := url.ParseQuery(returnURI)
		if err != nil {
			return err
		}
		r.Form = v
	}

	u.oauthCookie.ClearReturnURI(w)
	u.oauthCookie.ClearRedirectURI(w)
	ctx := moauth.WithUserIDContext(r.Context(), userID)

	return u.oauthServer.Srv.HandleAuthorizeRequest(w, r.WithContext(ctx))
}

func (u *oauthUsecase) RequestToken(w http.ResponseWriter, r *http.Request) error {
	return u.oauthServer.Srv.HandleTokenRequest(w, r)
}

func (u *oauthUsecase) VerifyToken(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	commons.DumpRequest(os.Stdout, "OAuthValidateTokenHandler", r) // Ignore the error

	token, err := u.oauthServer.Srv.ValidationBearerToken(r)
	if err != nil {
		return nil, err
	}
	commons.VerifyJWT(u.jwtSecret, token.GetAccess())

	t := token.GetAccessCreateAt().Add(token.GetAccessExpiresIn())
	expiresIn := int64(time.Until(t).Seconds())
	data := map[string]interface{}{
		// "expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
		"expires_in": expiresIn,
		"client_id":  token.GetClientID(),
		"user_id":    token.GetUserID(),
		"scope":      token.GetScope(),
	}
	return data, nil
}

func (u *oauthUsecase) AddClientCredential(clientID, clientSecret, clientDomain string) (map[string]interface{}, error) {

	err := u.oauthServer.ClientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: clientSecret,
		Domain: clientDomain,
	})
	if err != nil {
		return nil, err
	}
	data := map[string]interface{}{"client_id": clientID, "domain": clientDomain}
	return data, nil
}

func (u *oauthUsecase) Login(w http.ResponseWriter, r *http.Request) error {
	return u.authView.Login(w, r)
}
func (u *oauthUsecase) Authorize(w http.ResponseWriter, r *http.Request) error {
	return u.authView.Authorize(w, r)
}
