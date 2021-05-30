package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/go-session/session"
	"github.com/wonksing/oauth-server/pkg/commons"
)

var (
	dumpvar        bool
	addr           string
	configFileName string
)

func init() {
	flag.StringVar(&addr, "addr", ":9099", "listening address(eg. :9099)")
	flag.StringVar(&configFileName, "cn", "./configs/server.yml", "config file name")
	flag.BoolVar(&dumpvar, "d", true, "Dump requests and responses")
}

func main() {
	flag.Parse()
	if dumpvar {
		log.Println("Dumping requests")
	}

	http.HandleFunc("/", indexHandler)

	http.HandleFunc("/oauth/login", oauthLoginHandler)

	http.HandleFunc("/protected", protectedHandler)

	http.HandleFunc("/logout", logoutHandler)

	tmpAddr := addr
	if strings.HasPrefix(addr, ":") {
		tmpAddr = "localhost" + addr
	}
	log.Printf("Resource is running at %s. Please open http://%s", addr, tmpAddr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = commons.DumpRequest(os.Stdout, "indexHandler", r) // Ignore the error
	}

	commons.OutputHTML(w, r, "static/index.html")
}

func oauthLoginHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = commons.DumpRequest(os.Stdout, "oauthLoginHandler", r) // Ignore the error
	}

	if r.Form == nil {
		r.ParseForm()
	}

	redirectURI := r.Form.Get("redirect_uri")

	if redirectURI != "" {
		store, err := session.Start(context.Background(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Println(redirectURI)

		store.Set("redirect_uri", redirectURI)
		store.Save()
	}

	if r.Method == "GET" {
		commons.OutputHTML(w, r, "static/login.html")
		return
	}

	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	redirectURIStore, ok := store.Get("redirect_uri")
	if !ok {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if r.Form == nil {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	userID := r.Form.Get("user_id")
	userPW := r.Form.Get("user_pw")
	if len(userID) <= 0 {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if userID != userPW {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	store.Set("userID", userID)
	store.Save()

	redirectURI = redirectURIStore.(string)
	var buf bytes.Buffer
	buf.WriteString(redirectURI)
	v := url.Values{}
	v.Set("user_id", userID)
	v.Set("scope", "all")
	v.Set("allow_status", "yes")

	if strings.Contains(redirectURI, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	commons.Redirect(w, buf.String())

}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = commons.DumpRequest(os.Stdout, "protectedHandler", r) // Ignore the error
	}
	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, ok := store.Get("userID"); !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	commons.OutputHTML(w, r, "static/protected.html")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = commons.DumpRequest(os.Stdout, "logoutHandler", r) // Ignore the error
	}

	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = store.Flush()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	commons.OutputHTML(w, r, "static/index.html")
}
