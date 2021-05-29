package commons

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func SetCookie(w http.ResponseWriter, name, value string, validHours time.Duration) {

	ck := http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
		Path:     "/",
		Expires:  time.Now().Add(validHours * time.Hour),
	}
	http.SetCookie(w, &ck)
}

func OutputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
	// http.ServeContent(w, req, file.Name(), time.Now(), file)
}

func DumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}

func Redirect(w http.ResponseWriter, redirectURI string) {
	w.Header().Set("Location", redirectURI)
	w.WriteHeader(http.StatusFound)
}

type HttpServer struct {
	Router *mux.Router
	// Router  *http.ServeMux
	TLSConf *tls.Config
	server  *http.Server
	pem     string
	key     string
}

func NewHttpServer(addr string, writeTimeOutInSec int, readTimeOutInSec int, pem string, key string,
	allowedOrigins, allowedHeaders, allowedMethods []string) *HttpServer {
	var hs HttpServer

	hs.TLSConf = hs.createTLSConfigMinTls(tls.VersionTLS10)

	hs.server = &http.Server{
		Addr:         addr,
		TLSConfig:    hs.TLSConf,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		WriteTimeout: time.Duration(writeTimeOutInSec) * time.Second,
		ReadTimeout:  time.Duration(readTimeOutInSec) * time.Second,
	}
	hs.pem = pem
	hs.key = key

	router := mux.NewRouter()
	if len(allowedOrigins) == 0 && len(allowedHeaders) == 0 && len(allowedMethods) == 0 {
		hs.Router = router
		hs.server.Handler = router
	} else {
		corsOrigin := handlers.AllowedOrigins(allowedOrigins)
		corsHeaders := handlers.AllowedHeaders(allowedHeaders)
		corsMethods := handlers.AllowedMethods(allowedMethods)
		// nr := handlers.CORS(corsOrigin, corsHeaders, corsMethods)(hs.Router)
		cors := handlers.CORS(corsOrigin, corsHeaders, corsMethods)
		corsHandler := cors(router)

		hs.Router = router
		hs.server.Handler = corsHandler
	}

	// hs.addHandlers()
	return &hs
}

func (hs *HttpServer) createTLSConfig() *tls.Config {
	conf := &tls.Config{
		// MinVersion: tls.VersionTLS12,
		// MinVersion: tls.VersionTLS11,
		MinVersion:               tls.VersionTLS10, // weak, only for xp
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			// tls.TLS_RSA_WITH_RC4_128_SHA,
			// tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			// tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			// tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			// tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			// tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			// tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			// tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			// tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,

			// TLS 1.0 - 1.2 cipher suites.
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

			// TLS 1.3 cipher suites.
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
	return conf
}

func (hs *HttpServer) createTLSConfigMinTls(minTlsVersion uint16) *tls.Config {
	conf := &tls.Config{
		// MinVersion: tls.VersionTLS12,
		// MinVersion: tls.VersionTLS11,
		// MinVersion:               tls.VersionTLS10, // weak, only for xp
		MinVersion:               minTlsVersion, // weak, only for xp
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			// tls.TLS_RSA_WITH_RC4_128_SHA,
			// tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			// tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			// tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			// tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			// tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			// tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			// tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			// tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,

			// TLS 1.0 - 1.2 cipher suites.
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

			// TLS 1.3 cipher suites.
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
	return conf
}

func (hs *HttpServer) Start() error {
	var err error
	if len(hs.pem) > 0 || len(hs.key) > 0 {
		err = hs.server.ListenAndServeTLS(hs.pem, hs.key)
	} else {
		err = hs.server.ListenAndServe()
	}
	return err
}

func (hs *HttpServer) Stop() error {
	return hs.server.Shutdown(context.Background())
}
