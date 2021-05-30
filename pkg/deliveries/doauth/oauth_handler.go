package doauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/mjwt"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
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

	if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err := h.oauthUsc.Login(w, r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// OAuthLoginHandler 로그인 처리.
// GET 메소드면 로그인 페이지로 보내고, POST면 아이디와 비번을 검증한다.
func (h *OAuthHandler) AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthAuthenticateHandler", r) // Ignore the error

	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err := h.oauthUsc.Authenticate(w, r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = h.oauthUsc.RedirectToAuthorize(w, r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

}

// AccessHandler 엑세스 허용 페이지로 보낸다.
func (h *OAuthHandler) AccessHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthLoginHandler", r) // Ignore the error

	if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err := h.oauthUsc.Authorize(w, r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// AuthorizeAccessHandler 엑세스를 허용/거절한다
func (h *OAuthHandler) AuthorizeAccessHandler(w http.ResponseWriter, r *http.Request) {
	_ = commons.DumpRequest(os.Stdout, "AuthorizeAccessHandler", r) // Ignore the error

	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	ctx, err := h.oauthUsc.AuthorizeAccess(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.UserAuthorizeHandler(w, r.WithContext(ctx))

}

// UserAuthorizeHandler 인증&인가 확인 및 code 생성.
// 로그인 후 권한 인가를 허용한 사용자인 경우 auth code를 생성하여 redirect_uri 로 보낸다.
func (h *OAuthHandler) UserAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "UserAuthorizeHandler", r)

	err := h.oauthUsc.GrantAuthorizeCode(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// OAuthAuthorizeRedirectHandler 원격인증 방식으로 인증/인가할때 사용.
func (h *OAuthHandler) AuthorizeRemoteHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthAuthorizeRemoteHandler", r)

	err := h.oauthUsc.RedirectToLoginRemote(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// AuthorizeRemoteGrantHandler 리다이렉션 방식으로 인증/인가할때 사용.
func (h *OAuthHandler) AuthorizeRemoteGrantHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "AuthorizeRemoteGrantHandler", r)
	if r.Form == nil {
		r.ParseForm()
	}

	userID := r.Form.Get("user_id")
	// scope := r.Form.Get("scope")
	status := r.Form.Get("allow_status")
	token := r.Form.Get("token")
	claim, _, err := mjwt.ValidateAccessToken(token, "qwer")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.Form, err = url.ParseQuery(claim.UsrID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.oauthUsc.SetReturnURI(w, r)

	ctx := moauth.WithUserIDContext(r.Context(), userID)
	ctx = moauth.WithAllowStatusContext(ctx, status)

	err = h.oauthUsc.GrantAuthorizeCode(w, r.WithContext(ctx))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (h *OAuthHandler) OAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthTokenHandler", r) // Ignore the error

	err := h.oauthUsc.RequestToken(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *OAuthHandler) OAuthValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthValidateTokenHandler", r) // Ignore the error

	data, err := h.oauthUsc.VerifyToken(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(data)
}

func (h *OAuthHandler) CredentialHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	clientDomain := r.FormValue("client_domain")

	data, err := h.oauthUsc.AddClientCredential(clientID, clientSecret, clientDomain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(data)

}
