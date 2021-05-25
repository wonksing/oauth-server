package mjwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenClaim struct {
	UsrID string  `json:"usr_id"`
	Exp   float64 `json:"exp"`
}

func NewTokenClaim(usrID string, exp float64) *TokenClaim {
	return &TokenClaim{
		UsrID: usrID,
		Exp:   exp,
	}
}

func mapClaim(usrID string) *jwt.Token {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["usr_id"] = usrID
	claims["exp"] = time.Now().Add(1 * time.Minute).Unix()
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
	claim := NewTokenClaim(c["usr_id"].(string), c["exp"].(float64))
	return claim
}

func GenerateAccessToken(tokenSecret string, usrID string) (string, error) {
	token := mapClaim(usrID)

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
