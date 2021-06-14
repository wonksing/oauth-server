package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	API_OAUTH_AUTHORIZE        = "/oauth/authorize"
	API_OAUTH_AUTHORIZE_REMOTE = "/oauth/authorize/remote"
	API_OAUTH_TOKEN            = "/oauth/token"
	API_OAUTH_TOKEN_VALIDATE   = "/oauth/token/_validate"

	API_INDEX   = "/"
	API_REQUEST = "/req"
	API_OAUTH   = "/oauth2"
	API_REFRESH = "/refresh"
	API_TRY     = "/try"
	API_PWD     = "/pwd"
	API_CLIENT  = "/client"
)

var (
	globalToken    *oauth2.Token // Non-concurrent security
	globalState    string
	globalVerifier string
)

type ClientHandler struct {
	OAuthConfig   oauth2.Config
	AuthServerURL string
}

func (h *ClientHandler) AuthCodeRequest(w http.ResponseWriter, r *http.Request) {
	globalState = commons.RandStringBytes(5)
	globalVerifier = commons.RandStringBytes(16)
	u := h.OAuthConfig.AuthCodeURL(globalState,
		oauth2.SetAuthURLParam("code_challenge", moauth.GenCodeChallengeS256(globalVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	log.Println(globalState, globalVerifier)
	log.Println(u)

	http.Redirect(w, r, u, http.StatusFound)
}

func (h *ClientHandler) OauthHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	state := r.Form.Get("state")
	log.Println("state", state, "globalState", globalState)
	if state != globalState {
		http.Error(w, "State invalid", http.StatusBadRequest)
		return
	}
	code := r.Form.Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}
	token, err := h.OAuthConfig.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", globalVerifier))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	globalToken = token

	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(token)
}

func (h *ClientHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	if globalToken == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	globalToken.Expiry = time.Now()
	token, err := h.OAuthConfig.TokenSource(context.Background(), globalToken).Token()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	globalToken = token
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(token)
	log.Println(token)
}

func (h *ClientHandler) TryHandler(w http.ResponseWriter, r *http.Request) {
	if globalToken == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	resp, err := http.Get(fmt.Sprintf("%s%s?access_token=%s", h.AuthServerURL, API_OAUTH_TOKEN_VALIDATE, globalToken.AccessToken))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	io.Copy(w, resp.Body)
}

func (h *ClientHandler) PwdHandler(w http.ResponseWriter, r *http.Request) {
	token, err := h.OAuthConfig.PasswordCredentialsToken(context.Background(), "test", "test")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	globalToken = token
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(token)
}

func (h *ClientHandler) ClientHandler(w http.ResponseWriter, r *http.Request) {
	cfg := clientcredentials.Config{
		ClientID:     h.OAuthConfig.ClientID,
		ClientSecret: h.OAuthConfig.ClientSecret,
		TokenURL:     h.OAuthConfig.Endpoint.TokenURL,
	}

	token, err := cfg.Token(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(token)
}
