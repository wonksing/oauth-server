package views

import (
	"errors"
	"net/http"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/port"
)

type OAuthSelfView struct {
	loginHtml string
	authHtml  string
}

func NewOAuthSelfView(loginHtml, authHtml string) port.AuthView {
	return &OAuthSelfView{
		loginHtml: loginHtml,
		authHtml:  authHtml,
	}
}

func (v *OAuthSelfView) Login(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}
	if !commons.FileExists(v.loginHtml) {
		return errors.New("file not found")
	}
	commons.OutputHTML(w, r, v.loginHtml)
	return nil
}

func (v *OAuthSelfView) Authorize(w http.ResponseWriter, r *http.Request) error {
	if r.Form == nil {
		r.ParseForm()
	}
	if !commons.FileExists(v.authHtml) {
		return errors.New("file not found")
	}
	commons.OutputHTML(w, r, v.authHtml)
	return nil
}
