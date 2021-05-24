package deliveries

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/utils"
)

const (
	API_INDEX = "/"
	API_HELLO = "/hello"
	API_LOGIN = "/login"

	API_OAUTH_LOGIN          = "/oauth/login"
	API_OAUTH_ALLOW          = "/oauth/allow"
	API_OAUTH_AUTHORIZE      = "/oauth/authorize"
	API_OAUTH_TOKEN          = "/oauth/token"
	API_OAUTH_TOKEN_VALIDATE = "/oauth/token/_validate"
	API_OAUTH_CREDENTIALS    = "/credentials"

	HTML_HELLO       = "static/hello.html"
	HTML_LOGIN       = "static/login.html"
	HTML_OAUTH_LOGIN = "static/oauthlogin.html"
	HTML_OAUTH_ALLOW = "static/auth.html"
)

type ServerHandler struct {
	Srv         *server.Server
	JwtSecret   string
	ClientStore *store.ClientStore
}

func (h *ServerHandler) HelloHandler(w http.ResponseWriter, r *http.Request) {
	utils.OutputHTML(w, r, HTML_HELLO)
}

// LoginHandler 로그인 처리.
// GET 메소드면 로그인 페이지로 보내고, POST면 아이디와 비번을 검증한다.
func (h *ServerHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	utils.DumpRequest(os.Stdout, "LoginHandler", r) // Ignore the error

	if r.Form == nil {
		r.ParseForm()
	}
	if r.Method == "GET" {
		commons.SetCookie(w, "access_token", "", time.Duration(24*365))
		utils.OutputHTML(w, r, HTML_LOGIN)
		return
	}

	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// 인증
	userID := r.Form.Get("username")
	userPW := r.Form.Get("password")
	if userID != userPW {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	accessToken, err := commons.GenAccessTokenJWT(h.JwtSecret, userID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	commons.SetCookie(w, "access_token", accessToken, time.Duration(24*365))

	w.Header().Set("Location", API_HELLO)
	w.WriteHeader(http.StatusFound)

}

// UserAuthorizeHandler 인가된 사용자인지 확인한다.
// 로그인된 사용자라면 사용자 아이디를 반환하고, 그렇지 않으면 로그인 페이지로 유도한다.
// GET /oauth/authorize?client_id=12345&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8%3D&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A9094%2Foauth2&response_type=code&scope=all&state=xyz
func UserAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	utils.DumpRequest(os.Stdout, "UserAuthorizeHandler", r) // Ignore the error

	ctx := r.Context()
	claim := ctx.Value(commons.TokenClaim{})
	tc := claim.(*commons.TokenClaim)
	userID = tc.UsrID

	return
}

// LoginHandler 로그인 처리.
// GET 메소드면 로그인 페이지로 보내고, POST면 아이디와 비번을 검증한다.
func (h *ServerHandler) OAuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	utils.DumpRequest(os.Stdout, "OAuthLoginHandler", r) // Ignore the error

	if r.Form == nil {
		r.ParseForm()
	}
	if r.Method == "GET" {
		returnURICookie, err := r.Cookie("oauth_return_uri")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		commons.SetCookie(w, "access_token", "", time.Duration(24*365))
		commons.SetCookie(w, "oauth_return_uri", returnURICookie.Value, time.Duration(24*365))

		utils.OutputHTML(w, r, HTML_OAUTH_LOGIN)
		return
	}

	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// 인증
	userID := r.Form.Get("username")
	userPW := r.Form.Get("password")
	if userID != userPW {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	c1, err := r.Cookie("oauth_return_uri")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	fmt.Println(c1.Value)

	cliReturnUri := c1.Value
	// 리다이렉트 확인
	if cliReturnUri == "" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	accessToken, err := commons.GenAccessTokenJWT(h.JwtSecret, userID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	commons.SetCookie(w, "access_token", accessToken, time.Duration(24*365))
	commons.SetCookie(w, "oauth_return_uri", cliReturnUri, time.Duration(24*365))

	w.Header().Set("Location", API_OAUTH_ALLOW)
	w.WriteHeader(http.StatusFound)

}

func (h *ServerHandler) OAuthAllowAuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	_ = utils.DumpRequest(os.Stdout, "OAuthAllowAuthorizationHandler", r) // Ignore the error
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

	utils.OutputHTML(w, r, HTML_OAUTH_ALLOW)
}

// OAuthAuthHandler 인가된 사용자인지 확인한다.
// 로그인된 사용자라면 사용자 아이디를 반환하고, 그렇지 않으면 로그인 페이지로 유도한다.
// GET /oauth/authorize?client_id=12345&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8%3D&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A9094%2Foauth2&response_type=code&scope=all&state=xyz
func (h *ServerHandler) OAuthAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	utils.DumpRequest(os.Stdout, "OAuthAuthorizeHandler", r)

	if r.Form == nil {
		r.ParseForm()
	}

	// return_uri가 있는지 확인
	c1, _ := r.Cookie("oauth_return_uri")
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }
	// if c1 == nil {
	// 	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	// 	return
	// }
	if c1 != nil && c1.Value != "" {
		returnURI := c1.Value
		// oauth에 전달
		v, err := url.ParseQuery(returnURI)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		r.Form = v
	}

	// 쿠키에서 제거
	commons.SetCookie(w, "oauth_return_uri", "", time.Duration(24*365))

	err := h.Srv.HandleAuthorizeRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

}

func (h *ServerHandler) OAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	utils.DumpRequest(os.Stdout, "OAuthTokenHandler", r) // Ignore the error

	err := h.Srv.HandleTokenRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *ServerHandler) OAuthValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	utils.DumpRequest(os.Stdout, "OAuthValidateTokenHandler", r) // Ignore the error

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

func (h *ServerHandler) CredentialHandler(w http.ResponseWriter, r *http.Request) {
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
