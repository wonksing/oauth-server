package uoauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/wonksing/oauth-server/pkg/mocks"
	"github.com/wonksing/oauth-server/pkg/models/merror"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
	"github.com/wonksing/oauth-server/pkg/usecases/uoauth"
)

func createScopeMap() *moauth.OAuthScope {
	ar := moauth.AuthorizedResource{"/item", true, true, true, true}
	itemScope := make(moauth.AuthorizedResources, 0)
	itemScope = append(itemScope, ar)
	scopeMap := moauth.NewOAuthScope()
	scopeMap.Set("item", itemScope)

	return scopeMap
}
func TestSetClientReturnURI(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtSecret := "secret"
	jwtExpiresSecond := 60
	oauth2Auth := mocks.NewMockOAuth2Authorizer(ctrl)
	authRepo := mocks.NewMockAuthRepo(ctrl)
	authView := mocks.NewMockAuthView(ctrl)
	resRepo := mocks.NewMockResourceRepo(ctrl)
	scopeMap := createScopeMap()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	v := url.Values{}
	v.Set("client_id", "12345")
	v.Set("redirect_uri", "http://localhost:9094/oauth2")
	r.Form = v

	authRepo.EXPECT().SetClientReturnURI(w, r).AnyTimes().Return(nil)
	usc := uoauth.NewOAuthUsecase(jwtSecret, int64(jwtExpiresSecond), oauth2Auth, authRepo, authView, resRepo, scopeMap)

	err := usc.SetClientReturnURI(w, r)
	if !assert.Nil(t, err) {
		t.FailNow()
	}
}

func TestRedirectToLogin(t *testing.T) {
	var err error
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtSecret := "secret"
	jwtExpiresSecond := 60
	oauth2Auth := mocks.NewMockOAuth2Authorizer(ctrl)
	authRepo := mocks.NewMockAuthRepo(ctrl)
	authView := mocks.NewMockAuthView(ctrl)
	resRepo := mocks.NewMockResourceRepo(ctrl)
	scopeMap := createScopeMap()

	usc := uoauth.NewOAuthUsecase(jwtSecret, int64(jwtExpiresSecond), oauth2Auth, authRepo, authView, resRepo, scopeMap)

	// test normal case
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	v := url.Values{}
	v.Set("client_id", "12345")
	v.Set("redirect_uri", "http://localhost:9094/oauth2")
	r.Form = v

	authRepo.EXPECT().SetClientRedirectURI(w, r).Return(nil).AnyTimes()
	authRepo.EXPECT().SetClientReturnURI(w, r).Return(nil).AnyTimes()
	authRepo.EXPECT().RedirectToLogin(w, r).Return(nil).AnyTimes()

	err = usc.RedirectToLogin(w, r)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	// test no redirect_uri case
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/test", nil)
	v = url.Values{}
	v.Set("client_id", "12345")
	// v.Set("redirect_uri", "http://localhost:9094/oauth2")
	r.Form = v

	authRepo.EXPECT().SetClientRedirectURI(w, r).Return(merror.ErrorNoRedirectURI).AnyTimes()
	authRepo.EXPECT().SetClientReturnURI(w, r).Return(merror.ErrorNoRedirectURI).AnyTimes()
	authRepo.EXPECT().RedirectToLogin(w, r).Return(nil).AnyTimes()

	err = usc.RedirectToLogin(w, r)
	if !assert.Equal(t, merror.ErrorNoRedirectURI, err) {
		t.FailNow()
	}

	// test no client_id case
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/test", nil)
	v = url.Values{}
	// v.Set("client_id", "12345")
	v.Set("redirect_uri", "http://localhost:9094/oauth2")
	r.Form = v

	authRepo.EXPECT().SetClientRedirectURI(w, r).Return(nil).AnyTimes()
	authRepo.EXPECT().SetClientReturnURI(w, r).Return(merror.ErrorNoClientID).AnyTimes()
	authRepo.EXPECT().RedirectToLogin(w, r).Return(nil).AnyTimes()

	err = usc.RedirectToLogin(w, r)
	if !assert.Equal(t, merror.ErrorNoClientID, err) {
		t.FailNow()
	}
}

func TestAuthenticate(t *testing.T) {
	var err error
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtSecret := "secret"
	jwtExpiresSecond := 60
	oauth2Auth := mocks.NewMockOAuth2Authorizer(ctrl)
	authRepo := mocks.NewMockAuthRepo(ctrl)
	authView := mocks.NewMockAuthView(ctrl)
	resRepo := mocks.NewMockResourceRepo(ctrl)
	scopeMap := createScopeMap()

	usc := uoauth.NewOAuthUsecase(jwtSecret, int64(jwtExpiresSecond), oauth2Auth, authRepo, authView, resRepo, scopeMap)

	// test normal case
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	v := url.Values{}

	userID := "asdf"
	userPW := "asdf"
	v.Set("username", userID)
	v.Set("password", userPW)
	r.Form = v
	returnURI := "client_id=12345&redirect_uri=http://localhost:9094/oauth2&scope=all&state=xyz"
	resRepo.EXPECT().VerifyUserIDPW(userID, userPW).Return(userID, nil).AnyTimes()
	authRepo.EXPECT().GetReturnURI(r).Return(returnURI, nil).AnyTimes()
	authRepo.EXPECT().SetAccessToken(w, gomock.Any()).AnyTimes()

	err = usc.Authenticate(w, r)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

}

func TestGrantAuthorizeCode(t *testing.T) {
	var err error
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtSecret := "secret"
	jwtExpiresSecond := 60
	oauth2Auth := mocks.NewMockOAuth2Authorizer(ctrl)
	authRepo := mocks.NewMockAuthRepo(ctrl)
	authView := mocks.NewMockAuthView(ctrl)
	resRepo := mocks.NewMockResourceRepo(ctrl)
	scopeMap := createScopeMap()

	usc := uoauth.NewOAuthUsecase(jwtSecret, int64(jwtExpiresSecond), oauth2Auth, authRepo, authView, resRepo, scopeMap)

	// test normal case
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	v := url.Values{}

	userID := "asdf"
	// userPW := "asdf"
	status := "yes"
	// v.Set("username", userID)
	// v.Set("password", userPW)
	v.Set("client_id", "12345")
	v.Set("redirect_uri", "http://localhost:9094/oauth2")
	v.Set("scope", "all")
	v.Set("state", "xyz")
	r.Form = v
	returnURI := "client_id=12345&redirect_uri=http://localhost:9094/oauth2&scope=all&state=xyz"

	authRepo.EXPECT().GetUserID(r).Return(userID, nil).AnyTimes()
	authRepo.EXPECT().GetAuthStatus(r).Return(status, nil).AnyTimes()
	authRepo.EXPECT().GetReturnURI(r).Return(returnURI, nil).AnyTimes()
	authRepo.EXPECT().ClearClientReturnURI(w).AnyTimes()
	authRepo.EXPECT().ClearClientRedirectURI(w).AnyTimes()
	ctx := moauth.WithUserIDContext(r.Context(), userID)
	oauth2Auth.EXPECT().AuthorizeCode(w, r.WithContext(ctx)).Return(nil).AnyTimes()

	err = usc.GrantAuthorizeCode(w, r)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

}
