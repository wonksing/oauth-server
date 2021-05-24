package commons

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenClaim struct {
	UsrID string  `json:"usr_id"`
	Exp   float64 `json:"exp"`
}

func GenAccessTokenJWT(tokenSecret string, usrID string) (string, error) {

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["usr_id"] = usrID
	claims["exp"] = time.Now().Add(1 * time.Minute).Unix()

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

	var claim *TokenClaim
	if token != nil && token.Claims.Valid() != nil {
		c := token.Claims.(jwt.MapClaims)
		claim = &TokenClaim{
			UsrID: c["usr_id"].(string),
			Exp:   c["exp"].(float64),
		}
	}
	if err != nil {
		v, _ := err.(*jwt.ValidationError)
		if v.Errors == jwt.ValidationErrorExpired {
			return claim, true, err
		}
		return nil, false, err
	}

	if token.Valid {
		c := token.Claims.(jwt.MapClaims)
		claim = &TokenClaim{
			UsrID: c["usr_id"].(string),
			Exp:   c["exp"].(float64),
		}
		return claim, false, nil
	}

	return nil, false, errors.New(http.StatusText(http.StatusUnauthorized))
}
