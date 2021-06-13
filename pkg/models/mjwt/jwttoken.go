package mjwt

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/google/uuid"
)

// TokenClaim JWT 토큰 클레임 구조체이다.
// mjwt 패키지 안에서만 매핑하여 저장하고 가져오도록 하자
type TokenClaim struct {
	UsrID     string  `json:"usr_id,omitempty"`
	Exp       float64 `json:"exp,omitempty"`
	ReturnURI string  `json:"return_uri,omitempty"`
}

func NewTokenClaim(usrID string, exp float64, returnURI string) *TokenClaim {
	return &TokenClaim{
		UsrID:     usrID,
		Exp:       exp,
		ReturnURI: returnURI,
	}
}

func mapClaim(usrID string, expireTimeUnix int64, returnURI string) *jwt.Token {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["usr_id"] = usrID
	// claims["exp"] = time.Now().Add(time.Duration(expSecond) * time.Second).Unix()
	claims["exp"] = expireTimeUnix
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

func GenerateAccessToken(tokenSecret string, usrID string, expireTimeUnix int64, returnURI string) (string, error) {
	token := mapClaim(usrID, expireTimeUnix, returnURI)

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

// JWTAccessClaims jwt claims
type JWTAccessClaims struct {
	jwt.StandardClaims
	Scope string `json:"scope,omitempty"`
}

// Valid claims verification
func (a *JWTAccessClaims) Valid() error {
	if time.Unix(a.ExpiresAt, 0).Before(time.Now()) {
		return errors.ErrInvalidAccessToken
	}
	return nil
}

// NewJWTAccessGenerate create to generate the jwt access token instance
func NewJWTAccessGenerate(kid string, key []byte, method jwt.SigningMethod) *JWTAccessGenerate {
	return &JWTAccessGenerate{
		SignedKeyID:  kid,
		SignedKey:    key,
		SignedMethod: method,
	}
}

// JWTAccessGenerate generate the jwt access token
type JWTAccessGenerate struct {
	SignedKeyID  string
	SignedKey    []byte
	SignedMethod jwt.SigningMethod
}

// Token based on the UUID generated token
func (a *JWTAccessGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	claims := &JWTAccessClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  data.Client.GetID(),
			Subject:   data.UserID,
			ExpiresAt: data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
		},
		Scope: data.TokenInfo.GetScope(),
	}

	token := jwt.NewWithClaims(a.SignedMethod, claims)
	if a.SignedKeyID != "" {
		token.Header["kid"] = a.SignedKeyID
	}
	var key interface{}
	if a.isEs() {
		v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isRsOrPS() {
		v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isHs() {
		key = a.SignedKey
	} else {
		return "", "", errors.New("unsupported sign method")
	}

	access, err := token.SignedString(key)
	if err != nil {
		return "", "", err
	}
	refresh := ""

	if isGenRefresh {
		t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return access, refresh, nil
}

func (a *JWTAccessGenerate) isEs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "ES")
}

func (a *JWTAccessGenerate) isRsOrPS() bool {
	isRs := strings.HasPrefix(a.SignedMethod.Alg(), "RS")
	isPs := strings.HasPrefix(a.SignedMethod.Alg(), "PS")
	return isRs || isPs
}

func (a *JWTAccessGenerate) isHs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "HS")
}

func VerifyOAuthJWT(secret string, tokenStr string) (*JWTAccessClaims, error) {
	// Parse and verify jwt access token
	token, err := jwt.ParseWithClaims(tokenStr, &JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("parse error")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTAccessClaims)
	if !ok || !token.Valid {
		// panic("invalid token")
		return nil, errors.New("invalid token")
	}

	// fmt.Println(claims)
	// fmt.Println("claims:", claims.Audience, claims.Id, claims.Subject, claims.Scope)
	return claims, nil
}
