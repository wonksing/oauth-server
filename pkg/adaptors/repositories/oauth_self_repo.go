package repositories

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"

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

func (repo *OAuthSelfRepo) RedirectToLogin(w http.ResponseWriter, r *http.Request, redirectURI string) error {
	if r.Form == nil {
		r.ParseForm()
	}
	uri := repo.loginPageAPI
	if redirectURI != "" {
		var buf bytes.Buffer
		buf.WriteString(uri)
		v := url.Values{}
		v.Set("redirect_uri", redirectURI)

		if strings.Contains(uri, "?") {
			buf.WriteByte('&')
		} else {
			buf.WriteByte('?')
		}
		buf.WriteString(v.Encode())
		uri = buf.String()
	}
	commons.Redirect(w, uri)
	return nil
}

func (repo *OAuthSelfRepo) RedirectToAuthorize(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}

	commons.Redirect(w, repo.authorizePageAPI)
	return nil
}
