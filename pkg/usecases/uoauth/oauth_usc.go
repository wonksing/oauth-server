package uoauth

import (
	"net/http"
	"net/url"
	"os"
	"strings"

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

	// VerifyUserIDPW 사용자 아이디와 비번을 검증한다
	VerifyUserIDPW(userID, userPW string) (string, error)
	// Authenticate 사용자를 인증한다. 아이디&비번, return_uri 검증 후 AccessToken을 발행하여 쿠키에 저장
	Authenticate(w http.ResponseWriter, r *http.Request) error

	// RedirectToAuthorize 접근인가 페이지로 보낸다
	RedirectToAuthorize(w http.ResponseWriter, r *http.Request) error

	// GrantAuthorizeCode Authorization Code를 발급하여 클라이언트에 전달한다.
	// 사용자 인증과 인가 확인 후 발급한다.
	GrantAuthorizeCode(w http.ResponseWriter, r *http.Request) error

	// GrantedUserID 허용한 사용자 아이디
	GrantedUserID(w http.ResponseWriter, r *http.Request) (string, error)
	// GrantedScope 허용한 Scope
	GrantedScope(w http.ResponseWriter, r *http.Request) (scope string, err error)
	// GrnatScopeByClient Client별 허용된 Scope을 구한다
	GrnatScopeByClient(clientID, requestedScope string) (scope string, err error)

	// RequestToken AccessToken을 발급해준다
	RequestToken(w http.ResponseWriter, r *http.Request) error

	// VerifyToken 토큰을 검증한다.
	VerifyToken(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error)

	// AddClientCredential 새로운 클라이언트를 추가한다.
	AddClientCredential(clientID, clientSecret, clientDomain, scope string) (map[string]interface{}, error)

	// views
	// Login 페이지
	Login(w http.ResponseWriter, r *http.Request) error
	// Authorize 페이지, 클라이언트에게 접근을 인가하는 페이지
	Authorize(w http.ResponseWriter, r *http.Request) error
}

type oauthUsecase struct {
	jwtSecret        string
	jwtExpiresSecond int64
	oauth2Authorizer port.OAuth2Authorizer
	authRepo         port.AuthRepo
	authView         port.AuthView
	resRepo          port.ResourceRepo
	scopeMap         *moauth.OAuthScope
}

func NewOAuthUsecase(
	jwtSecret string,
	jwtExpiresSecond int64,
	oauth2Authorizer port.OAuth2Authorizer,
	authRepo port.AuthRepo,
	authView port.AuthView,
	resRepo port.ResourceRepo,
	scopeMap *moauth.OAuthScope,
) Usecase {

	usc := &oauthUsecase{
		jwtSecret:        jwtSecret,
		jwtExpiresSecond: jwtExpiresSecond,
		oauth2Authorizer: oauth2Authorizer,
		authRepo:         authRepo,
		authView:         authView,
		resRepo:          resRepo,
		scopeMap:         scopeMap,
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
func (u *oauthUsecase) VerifyUserIDPW(userID, userPW string) (string, error) {
	return u.resRepo.VerifyUserIDPW(userID, userPW)
}
func (u *oauthUsecase) Authenticate(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	userID := r.Form.Get("username")
	userPW := r.Form.Get("password")
	_, err := u.resRepo.VerifyUserIDPW(userID, userPW)
	if err != nil {
		return err
	}

	returnURI, err := u.authRepo.GetReturnURI(r)
	if err != nil {
		return err
	}
	if returnURI == "" {
		return merror.ErrorNoReturnURI
	}

	accessToken, err := mjwt.GenerateAccessToken(u.jwtSecret, userID, u.jwtExpiresSecond, "")
	if err != nil {
		return err
	}

	u.authRepo.SetAccessToken(w, accessToken)
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

	u.authRepo.ClearClientReturnURI(w)
	u.authRepo.ClearClientRedirectURI(w)
	ctx := moauth.WithUserIDContext(r.Context(), userID)

	return u.oauth2Authorizer.AuthorizeCode(w, r.WithContext(ctx))
}
func (u *oauthUsecase) GrantedUserID(w http.ResponseWriter, r *http.Request) (string, error) {
	userID, err := moauth.GetUserIDContext(r.Context())
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(userID) == "" {
		return "", merror.ErrorUserIDNotFound
	}
	return userID, err
}
func (u *oauthUsecase) GrantedScope(w http.ResponseWriter, r *http.Request) (scope string, err error) {
	// authorization code 를 요청할 때, 요청 파라메터의 client_id와 scope를 이용해서
	// 허용된 scope을 구한다.

	if r.Form == nil {
		r.ParseForm()
	}
	clientID := r.Form.Get("client_id")
	requestedScope := r.Form.Get("scope")

	scope, err = u.GrnatScopeByClient(clientID, requestedScope)
	return
}

func (u *oauthUsecase) GrnatScopeByClient(clientID, requestedScope string) (scope string, err error) {
	ci, err := u.oauth2Authorizer.GetClientByID(clientID)
	if err != nil {
		return
	}
	allowedScope := ci.GetScope()
	filteredScope, err := u.scopeMap.FilterScope(allowedScope, requestedScope)
	if err != nil {
		return
	}

	scope = u.scopeMap.PickAllowedScope(filteredScope)
	if scope == "" {
		err = merror.ErrorNoAllowedScope
		return
	}
	return
}

func (u *oauthUsecase) RequestToken(w http.ResponseWriter, r *http.Request) error {
	return u.oauth2Authorizer.Token(w, r)
}

func (u *oauthUsecase) VerifyToken(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	commons.DumpRequest(os.Stdout, "OAuthValidateTokenHandler", r) // Ignore the error

	accessToken, expiresIn, clientID, userID, scope, err := u.oauth2Authorizer.ValidateToken(r)
	if err != nil {
		return nil, err
	}
	commons.VerifyJWT(u.jwtSecret, accessToken)

	data := map[string]interface{}{
		"expires_in": expiresIn,
		"client_id":  clientID,
		"user_id":    userID,
		"scope":      scope,
	}
	return data, nil
}

func (u *oauthUsecase) AddClientCredential(clientID, clientSecret, clientDomain, scope string) (map[string]interface{}, error) {
	err := u.oauth2Authorizer.AddClient(clientID, clientSecret, clientDomain, scope)
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
