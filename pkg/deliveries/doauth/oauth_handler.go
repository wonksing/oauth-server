package doauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/usecases/uoauth"
)

const (
	API_OAUTH_LOGIN          = "/oauth/login"
	API_OAUTH_AUTHENTICATE   = "/oauth/authenticate"
	API_OAUTH_ALLOW          = "/oauth/allow"
	API_OAUTH_AUTHORIZE      = "/oauth/authorize"
	API_OAUTH_TOKEN          = "/oauth/token"
	API_OAUTH_TOKEN_VALIDATE = "/oauth/token/_validate"
	API_OAUTH_CREDENTIALS    = "/oauth/credentials"

	HTML_OAUTH_LOGIN = "static/oauth/login.html"
	HTML_OAUTH_ALLOW = "static/oauth/allow.html"
)

type OAuthHandler struct {
	Srv         *server.Server
	JwtSecret   string
	ClientStore *store.ClientStore

	oauthUsc uoauth.Usecase
}

func NewOAuthHandler(
	oauthUsc uoauth.Usecase,
	Srv *server.Server,
	JwtSecret string,
	ClientStore *store.ClientStore,
) *OAuthHandler {
	return &OAuthHandler{
		oauthUsc:    oauthUsc,
		Srv:         Srv,
		JwtSecret:   JwtSecret,
		ClientStore: ClientStore,
	}

}

// LoginHandler 로그인 페이지로 보낸다.
func (h *OAuthHandler) OAuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthLoginHandler", r) // Ignore the error

	if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if r.Form == nil {
		r.ParseForm()
	}

	err := h.oauthUsc.BeforeAuthenticate(w, r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// returnUri, err := h.oauthUsc.ReadReturnURI(r)
	// if err != nil {
	// 	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	// 	return
	// }
	// h.oauthUsc.ClearAccessToken(w)
	// h.oauthUsc.WriteReturnURI(w, returnUri)

	commons.OutputHTML(w, r, HTML_OAUTH_LOGIN)
	return
}

// OAuthLoginHandler 로그인 처리.
// GET 메소드면 로그인 페이지로 보내고, POST면 아이디와 비번을 검증한다.
func (h *OAuthHandler) OAuthAuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthAuthenticateHandler", r) // Ignore the error

	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if r.Form == nil {
		r.ParseForm()
	}

	// 인증
	userID := r.Form.Get("username")
	userPW := r.Form.Get("password")
	err := h.oauthUsc.Authenticate(userID, userPW)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = h.oauthUsc.AfterAuthenticate(w, r, userID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Location", API_OAUTH_ALLOW)
	w.WriteHeader(http.StatusFound)

}

// OAuthAllowHandler 사용자가 권한을 허용한다.
func (h *OAuthHandler) OAuthAllowHandler(w http.ResponseWriter, r *http.Request) {
	_ = commons.DumpRequest(os.Stdout, "OAuthAllowHandler", r) // Ignore the error
	// store, err := session.Start(r.Context(), w, r)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	// if _, ok := store.Get("LoggedInUserID"); !ok {
	// 	w.Header().Set("Location", "/oauthlogin")
	// 	w.WriteHeader(http.StatusFound)
	// 	return
	// }

	commons.OutputHTML(w, r, HTML_OAUTH_ALLOW)
}

// OAuthAuthHandler 인가된 사용자인지 확인한다.
// 로그인된 사용자라면 사용자 아이디를 반환하고, 그렇지 않으면 로그인 페이지로 유도한다.
// GET /oauth/authorize?client_id=12345&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8%3D&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A9094%2Foauth2&response_type=code&scope=all&state=xyz
func (h *OAuthHandler) OAuthAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthAuthorizeHandler", r)

	if r.Form == nil {
		r.ParseForm()
	}

	err := h.oauthUsc.BeforeUserAuthorize(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.Srv.HandleAuthorizeRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

}

func (h *OAuthHandler) OAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthTokenHandler", r) // Ignore the error

	err := h.Srv.HandleTokenRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *OAuthHandler) OAuthValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "OAuthValidateTokenHandler", r) // Ignore the error

	token, err := h.Srv.ValidationBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	commons.VerifyJWT(h.JwtSecret, token.GetAccess())

	t := token.GetAccessCreateAt().Add(token.GetAccessExpiresIn())
	expiresIn := int64(time.Until(t).Seconds())
	data := map[string]interface{}{
		// "expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
		"expires_in": expiresIn,
		"client_id":  token.GetClientID(),
		"user_id":    token.GetUserID(),
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

	err := h.ClientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: clientSecret,
		Domain: clientDomain,
	})
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"CLIENT_ID": clientID, "CLIENT_SECRET": clientSecret})
}
