package port

import "net/http"

type OAuthCookie interface {
	ReadReturnURI(r *http.Request) (string, error)
	WriteReturnURI(w http.ResponseWriter, returnURI string)
	ClearReturnURI(w http.ResponseWriter)

	ReadAccessToken(r *http.Request) (string, error)
	WriteAccessToken(w http.ResponseWriter, accessToken string)
	ClearAccessToken(w http.ResponseWriter)

	ReadRedirectURI(r *http.Request) (string, error)
	WriteRedirectURI(w http.ResponseWriter, redirectURI string)
	ClearRedirectURI(w http.ResponseWriter)
}

type AuthRepo interface {
	// SetReturnURI 사용자가 Code Authorization을 최초로 요청했을 때
	// 인증이 되어 있지 않다면 return uri를 쿠키에 저장한다.
	SetReturnURI(w http.ResponseWriter, r *http.Request) error
	GetReturnURI(r *http.Request) (string, error)
	ClearReturnURI(w http.ResponseWriter)
	SetRedirectURI(w http.ResponseWriter, r *http.Request) error
	GetRedirectURI(r *http.Request) (string, error)
	ClearRedirectURI(w http.ResponseWriter)

	RedirectToClient(w http.ResponseWriter, r *http.Request) error

	Login(w http.ResponseWriter, r *http.Request) error
	Authenticate(w http.ResponseWriter, r *http.Request, jwtSecret string, jwtExpiresSecond int64) error
	Access(w http.ResponseWriter, r *http.Request) error
	AuthorizeAccess(w http.ResponseWriter, r *http.Request) string
	// UserAuthorize(w http.ResponseWriter, r *http.Request) error
	CheckUserID(r *http.Request) (string, error)
	CheckAuthorizeStatus(r *http.Request) (string, error)
}
