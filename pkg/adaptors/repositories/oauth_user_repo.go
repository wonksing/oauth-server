package repositories

import (
	"github.com/wonksing/oauth-server/pkg/models/merror"
	"github.com/wonksing/oauth-server/pkg/port"
)

type OAuthUserRepo struct {
}

func NewOAuthUserRepo() port.ResourceRepo {
	return &OAuthUserRepo{}
}

func (repo *OAuthUserRepo) VerifyUserIDPW(userID, userPW string) (string, error) {
	// TODO Must Change
	if userID != userPW {
		return "", merror.ErrorUserIDNotFound
	}

	return userID, nil
}
