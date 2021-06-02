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
	ClearClientReturnURI(w http.ResponseWriter)

	SetClientReturnURI(w http.ResponseWriter, r *http.Request) error

	ClearClientRedirectURI(w http.ResponseWriter)

	SetClientRedirectURI(w http.ResponseWriter, r *http.Request) error

	RedirectToClient(w http.ResponseWriter, r *http.Request) error

	SetAccessToken(w http.ResponseWriter, accessToken string)

	ClearAccessToken(w http.ResponseWriter)

	GetUserID(r *http.Request) (string, error)
	GetAuthStatus(r *http.Request) (string, error)
	GetReturnURI(r *http.Request) (string, error)

	RedirectToLogin(w http.ResponseWriter, r *http.Request) error
	RedirectToAuthorize(w http.ResponseWriter, r *http.Request) error
}

type AuthView interface {
	Login(w http.ResponseWriter, r *http.Request) error
	Authorize(w http.ResponseWriter, r *http.Request) error
}

type ResourceRepo interface {
	Authenticate(userID, userPW string) error
}
