package uoauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/wonksing/oauth-server/pkg/mocks"
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
