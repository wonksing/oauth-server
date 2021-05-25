package filerepo

import (
	"errors"

	"github.com/wonksing/oauth-server/pkg/port"
)

type AuthFileRepo struct {
}

func NewAuthFileRepo() port.AuthRepo {
	return &AuthFileRepo{}
}

func (repo *AuthFileRepo) Authenticate(userID, userPW string) error {
	if userID != userPW {
		return errors.New("user ID and password does not match")
	}
	return nil
}
