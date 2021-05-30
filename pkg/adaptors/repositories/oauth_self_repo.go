package repositories

import (
	"net/http"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/port"
)

type OAuthSelfRepo struct {
	loginPageAPI     string
	authorizePageAPI string
}

func NewOAuthSelfRepo(loginPageAPI string, authorizePageAPI string) port.AuthRepo {
	return &OAuthSelfRepo{
		loginPageAPI:     loginPageAPI,
		authorizePageAPI: authorizePageAPI,
	}
}

func (repo *OAuthSelfRepo) RedirectToLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	commons.Redirect(w, repo.loginPageAPI)
	return nil
}

func (repo *OAuthSelfRepo) RedirectToAuthorize(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	commons.Redirect(w, repo.authorizePageAPI)
	return nil
}
