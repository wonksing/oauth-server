package uoauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-oauth2/oauth2/models"
	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/port"
)

type Usecase interface {

	// SetReturnURI 사용자가 Code Authorization 요청 직후
	// 인증이 되어 있지 않다면 return uri를 쿠키에 저장한다.
	SetReturnURI(w http.ResponseWriter, r *http.Request) error
	// SetRedirectURI 인가를 거부했을 때 돌려보내줄 URI
	SetRedirectURI(w http.ResponseWriter, r *http.Request) error
	// RedirectToClient Client에게 돌려보내기(인가 거부시)
	RedirectToClient(w http.ResponseWriter, r *http.Request) error

	// Login 로그인 페이지로 보내기
	Login(w http.ResponseWriter, r *http.Request) error

	// Authenticate 사용자 인증
	// 사용자의 ID와 PW 검사, return uri 유무 확인 후 이상 없으면
	// access token을 생성하여 쿠키에 저장하고 인가 페이지로 보낸다.
	Authenticate(w http.ResponseWriter, r *http.Request) error

	// Access 인가 페이지로 보낸다
	// TODO rename this function name
	Access(w http.ResponseWriter, r *http.Request) error
	// AuthorizeAccess 접근을 인가한다. 허용 또는 거부
	// TODO 여기 아니면 Grant에서 Scope을 처리해야한다.
	AuthorizeAccess(w http.ResponseWriter, r *http.Request) (context.Context, error)

	// GrantAuthorizeCode Authorization Code를 발급하여 클라이언트에 전달한다.
	// 사용자 인증과 인가 확인 후 발급한다.
	GrantAuthorizeCode(w http.ResponseWriter, r *http.Request) error
	// RequestToken AccessToken을 발급해준다
	RequestToken(w http.ResponseWriter, r *http.Request) error
	// VerifyToken 토큰을 검증한다.
	VerifyToken(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error)
	// AddClientCredential 새로운 클라이언트를 추가한다.
	// Store에 자동으로 저장되지는 않는다.
	AddClientCredential(clientID, clientSecret, clientDomain string) (map[string]interface{}, error)
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
	u.authRepo.ClearRedirectURI(w)
	if returnURI != "" {
		// oauth에 전달할 파라메터 다시 붙여주기(client_id, redirect_uri 등)
		v, err := url.ParseQuery(returnURI)
		if err != nil {
			return err
		}
		r.Form = v
	}

	return u.oauthServer.Srv.HandleAuthorizeRequest(w, r)
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
	}
	// e := json.NewEncoder(w)
	// e.SetIndent("", "  ")
	// e.Encode(data)
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
	data := map[string]interface{}{"CLIENT_ID": clientID, "CLIENT_SECRET": clientSecret}
	return data, nil
	// w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(map[string]string{"CLIENT_ID": clientID, "CLIENT_SECRET": clientSecret})
}
