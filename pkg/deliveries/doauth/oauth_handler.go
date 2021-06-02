package doauth

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/merror"
	"github.com/wonksing/oauth-server/pkg/usecases/uoauth"
)

type OAuthHandler struct {
	oauthUsc uoauth.Usecase
}

func NewOAuthHandler(oauthUsc uoauth.Usecase) *OAuthHandler {
	return &OAuthHandler{
		oauthUsc: oauthUsc,
	}

}

// LoginHandler 로그인 페이지로 보낸다.
func (h *OAuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthLoginHandler", r) // Ignore the error

	err := h.oauthUsc.Login(w, r)
	if err != nil {
		merror.HttpRespond(w, http.StatusInternalServerError, err)
		return
	}
}

// OAuthLoginHandler 로그인 처리.
// GET 메소드면 로그인 페이지로 보내고, POST면 아이디와 비번을 검증한다.
func (h *OAuthHandler) AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthAuthenticateHandler", r) // Ignore the error

	err := h.oauthUsc.Authenticate(w, r)
	if err != nil {
		merror.HttpRespond(w, http.StatusInternalServerError, err)
		return
	}

	err = h.oauthUsc.RedirectToAuthorize(w, r)
	if err != nil {
		merror.HttpRespond(w, http.StatusInternalServerError, err)
		return
	}

}

// AccessHandler 엑세스 허용 페이지로 보낸다.
func (h *OAuthHandler) AccessHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthLoginHandler", r) // Ignore the error

	err := h.oauthUsc.Authorize(w, r)
	if err != nil {
		merror.HttpRespond(w, http.StatusInternalServerError, err)
		return
	}
}

// GrantAuthorizeCodeHandler 인증&인가 확인 및 code 생성.
// 로그인 후 권한 인가를 허용한 사용자인 경우 auth code를 생성하여 redirect_uri 로 보낸다.
func (h *OAuthHandler) GrantAuthorizeCodeHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "GrantAuthorizeCodeHandler", r)

	err := h.oauthUsc.GrantAuthorizeCode(w, r)
	if err != nil {
		merror.HttpRespond(w, http.StatusInternalServerError, err)
		// http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (h *OAuthHandler) OAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthTokenHandler", r) // Ignore the error

	err := h.oauthUsc.RequestToken(w, r)
	if err != nil {
		merror.HttpRespond(w, http.StatusInternalServerError, err)
	}
}

func (h *OAuthHandler) OAuthValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthValidateTokenHandler", r) // Ignore the error

	data, err := h.oauthUsc.VerifyToken(w, r)
	if err != nil {
		merror.HttpRespond(w, http.StatusInternalServerError, err)
		return
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(data)
}

func (h *OAuthHandler) CredentialHandler(w http.ResponseWriter, r *http.Request) {

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	clientDomain := r.FormValue("client_domain")
	clientScope := r.FormValue("client_scope")

	data, err := h.oauthUsc.AddClientCredential(clientID, clientSecret, clientDomain, clientScope)
	if err != nil {
		merror.HttpRespond(w, http.StatusInternalServerError, err)
		return
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(data)

}
