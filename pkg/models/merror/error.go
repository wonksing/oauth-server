package merror

type Error interface {
	// ReplaceError(err error) (string, string)
	error
}
type OAuthError struct {
	ErrMsg  string
	ErrCode string
}

func NewOAuthError(errCode, errMsg string) Error {
	return &OAuthError{
		ErrMsg:  errMsg,
		ErrCode: errCode,
	}
}

func (o *OAuthError) Error() string {
	return "(" + o.ErrCode + ")" + o.ErrMsg
}

var (
	ErrorUserIDNotFound  = NewOAuthError("1002", "사용자 아이디가 없습니다").(*OAuthError)
	ErrorUserNeedToAllow = NewOAuthError("1000", "사용자의 권한 허용이 필요합니다").(*OAuthError)
	ErrorUserDidNotAllow = NewOAuthError("1001", "사용자가 권한 사용을 거절하였습니다").(*OAuthError)
	ErrorNotAllowedScop  = NewOAuthError("1003", "client scope is not allowed").(*OAuthError)
)
