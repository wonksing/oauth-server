package cookies

import (
	"net/http"
	"time"

	"github.com/wonksing/oauth-server/pkg/commons"
	"github.com/wonksing/oauth-server/pkg/port"
)

type oauthCookie struct {
	returnURIKey          string
	returnURIDurationHour time.Duration

	accessTokenKey          string
	accessTokenDurationHour time.Duration
}

func NewOAuthCookie(
	returnURIKey string, returnURIDurationHour time.Duration,
	accessTokenKey string, accessTokenDurationHour time.Duration,
) port.OAuthCookie {
	return &oauthCookie{
		returnURIKey:            returnURIKey,
		returnURIDurationHour:   returnURIDurationHour,
		accessTokenKey:          accessTokenKey,
		accessTokenDurationHour: accessTokenDurationHour,
	}
}

func (repo *oauthCookie) ReadReturnURI(r *http.Request) (string, error) {
	returnURI, err := r.Cookie(repo.returnURIKey)
	if err != nil {
		return "", err
	}
	return returnURI.Value, nil
}
func (repo *oauthCookie) WriteReturnURI(w http.ResponseWriter, returnURI string) {
	commons.SetCookie(w, repo.returnURIKey, returnURI, repo.returnURIDurationHour)
}

func (repo *oauthCookie) ClearReturnURI(w http.ResponseWriter) {
	commons.SetCookie(w, repo.returnURIKey, "", repo.returnURIDurationHour)
}

func (repo *oauthCookie) ReadAccessToken(r *http.Request) (string, error) {
	c, err := r.Cookie(repo.accessTokenKey)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}
func (repo *oauthCookie) WriteAccessToken(w http.ResponseWriter, accessToken string) {
	commons.SetCookie(w, repo.accessTokenKey, accessToken, repo.accessTokenDurationHour)
}

func (repo *oauthCookie) ClearAccessToken(w http.ResponseWriter) {
	commons.SetCookie(w, repo.accessTokenKey, "", repo.accessTokenDurationHour)
}
