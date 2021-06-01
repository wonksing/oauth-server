package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/wonksing/oauth-server/example/clientserver/handler"
	"golang.org/x/oauth2"
)

var (
	Version = "1.1.1"
)

func requestAuthorize() {
	// GET 호출
	resp, err := http.Get("http://localhost:9096/token?grant_type=client_credentials&client_id=12341234&client_secret=12341234&scope=all")
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	// 결과 출력
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", string(data))
}

func main() {
	printVersion := false
	var tickIntervalSec int = 30
	addr := ""
	authServerURL := ""
	redirectURL := ""
	flag.BoolVar(&printVersion, "version", false, "print version")
	flag.IntVar(&tickIntervalSec, "tick", 30, "tick interval in second")
	flag.StringVar(&addr, "addr", ":9094", ":9094")
	flag.StringVar(&authServerURL, "authserver", "http://localhost:9096", "http://localhost:9096")
	flag.StringVar(&redirectURL, "redirecturl", "http://localhost:9094/oauth2", "http://localhost:9094/oauth2")
	flag.Parse()

	if printVersion {
		fmt.Printf("version \"%v\"\n", Version)
		return
	}

	config := oauth2.Config{
		ClientID:     "12345",
		ClientSecret: "12345678",
		Scopes:       []string{"all"},
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authServerURL + handler.API_OAUTH_AUTHORIZE,
			TokenURL: authServerURL + handler.API_OAUTH_TOKEN,
		},
	}

	h := &handler.ClientHandler{
		OAuthConfig:   config,
		AuthServerURL: authServerURL,
	}

	http.HandleFunc(handler.API_REQUEST, h.AuthCodeRequest)

	http.HandleFunc(handler.API_OAUTH, h.OauthHandler)

	http.HandleFunc(handler.API_REFRESH, h.RefreshHandler)

	http.HandleFunc(handler.API_TRY, h.TryHandler)

	http.HandleFunc(handler.API_PWD, h.PwdHandler)

	http.HandleFunc(handler.API_CLIENT, h.ClientHandler)

	log.Println("Client is running on " + addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
