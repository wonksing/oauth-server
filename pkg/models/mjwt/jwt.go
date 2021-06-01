package mjwt

import (
	"context"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// TokenClaim JWT 토큰 클레임 구조체이다.
// mjwt 패키지 안에서만 매핑하여 저장하고 가져오도록 하자
type TokenClaim struct {
	UsrID     string  `json:"usr_id,omitempty"`
	Exp       float64 `json:"exp,omitempty"`
	ReturnURI string  `json:return_uri,omitempty`
}

func NewTokenClaim(usrID string, exp float64, returnURI string) *TokenClaim {
	return &TokenClaim{
		UsrID:     usrID,
		Exp:       exp,
		ReturnURI: returnURI,
	}
}

func mapClaim(usrID string, expSecond int64, returnURI string) *jwt.Token {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["usr_id"] = usrID
	claims["exp"] = time.Now().Add(time.Duration(expSecond) * time.Second).Unix()
	claims["return_uri"] = returnURI
	return token
}

func getTokenClaim(token *jwt.Token) *TokenClaim {
	if token == nil {
		return nil
	}
	if token.Claims.Valid() != nil {
		return nil
	}

	c := token.Claims.(jwt.MapClaims)
	claim := NewTokenClaim(c["usr_id"].(string), c["exp"].(float64), c["return_uri"].(string))
	return claim
}

func GenerateAccessToken(tokenSecret string, usrID string, expSecond int64, returnURI string) (string, error) {
	token := mapClaim(usrID, expSecond, returnURI)

	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// ValidateAccessToken 액세스토큰의 유효성을 판단하고 리프레시 가능한지 확인
// bool은 expired 됐는지 여부이다.
func ValidateAccessToken(accessToken string, tokenSecret string) (*TokenClaim, bool, error) {
	// Parse takes the token string and a function for looking up the key.
	// The latter is especially useful if you use multiple keys for your application.
	// The standard is to use 'kid' in the head of the token to identify
	// which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(tokenSecret), nil
	})

	if err != nil {
		v, _ := err.(*jwt.ValidationError)
		if v.Errors == jwt.ValidationErrorExpired && token.Valid {
			claim := getTokenClaim(token)
			return claim, true, err
		}
		return nil, false, err
	}

	claim := getTokenClaim(token)
	return claim, false, nil
}

func WithTokenClaimContext(ctx context.Context, claim *TokenClaim) context.Context {
	return context.WithValue(ctx, TokenClaim{}, claim)
}

func GetTokenClaimContext(ctx context.Context) *TokenClaim {
	tmp := ctx.Value(TokenClaim{})
	if tmp == nil {
		return nil
	}
	return tmp.(*TokenClaim)
}
