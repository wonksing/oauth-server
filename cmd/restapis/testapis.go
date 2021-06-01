package restapis

import (
	"github.com/gorilla/mux"
	"github.com/wonksing/oauth-server/pkg/deliveries/dmiddleware"
	"github.com/wonksing/oauth-server/pkg/deliveries/duser"
)

func RegisterTestAPIs(router *mux.Router, jwtMiddleware *dmiddleware.JWTMiddleware, handler *duser.HttpUserHandler) {

	router.HandleFunc(duser.API_INDEX, handler.IndexHandler).Methods("GET")
	router.HandleFunc(duser.API_LOGIN, handler.LoginHandler).Methods("GET")
	router.HandleFunc(duser.API_AUTHENTICATE, handler.AuthenticateHandler).Methods("POST")
	router.HandleFunc(duser.API_HELLO, jwtMiddleware.AuthJWTHandler(handler.HelloHandler, duser.API_LOGIN)).Methods("GET")
}
