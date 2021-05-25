package duser

import (
	"net/http"
	"os"
	"time"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/mjwt"
)

const (
	API_INDEX        = "/"
	API_HELLO        = "/hello"
	API_LOGIN        = "/login"
	API_AUTHENTICATE = "/authenticate"
	HTML_INDEX       = "static/index.html"
	HTML_HELLO       = "static/hello.html"
	HTML_LOGIN       = "static/login.html"
	HTML_OAUTH_LOGIN = "static/oauthlogin.html"
	HTML_OAUTH_ALLOW = "static/auth.html"
)

type HttpUserHandler struct {
	jwtSecret string
}

func NewHttpUserHandler(jwtSecret string) *HttpUserHandler {
	return &HttpUserHandler{
		jwtSecret: jwtSecret,
	}
}

// LoginHandler GET 메소드면 로그인 페이지로 보낸다
func (h *HttpUserHandler) IndexHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "IndexHandler", r) // Ignore the error

	if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	commons.OutputHTML(w, r, HTML_INDEX)
	return
}

// LoginHandler GET 메소드면 로그인 페이지로 보낸다
func (h *HttpUserHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "LoginHandler", r) // Ignore the error

	if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if r.Form == nil {
		r.ParseForm()
	}
	commons.SetCookie(w, "access_token", "", time.Duration(24*365))
	commons.OutputHTML(w, r, HTML_LOGIN)
	return
}

// AuthenticateHandler 아이디와 비번을 인증한다.
func (h *HttpUserHandler) AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	commons.DumpRequest(os.Stdout, "LoginHandler", r) // Ignore the error
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if r.Form == nil {
		r.ParseForm()
	}

	// 인증
	userID := r.Form.Get("username")
	userPW := r.Form.Get("password")
	if userID != userPW {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	accessToken, err := mjwt.GenerateAccessToken(h.jwtSecret, userID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	commons.SetCookie(w, "access_token", accessToken, time.Duration(24*365))

	w.Header().Set("Location", API_HELLO)
	w.WriteHeader(http.StatusFound)

}

func (h *HttpUserHandler) HelloHandler(w http.ResponseWriter, r *http.Request) {
	commons.OutputHTML(w, r, HTML_HELLO)
}
