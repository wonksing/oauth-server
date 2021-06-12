package mjwt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/wonksing/oauth-server/pkg/models/mjwt"
)

func TestGenerateAccessToken(t *testing.T) {
	tokenSecret := "asdfasdf1234"
	userID := "wonk"

	testTimeStr := "20220101120303"
	tim, _ := time.Parse("20060102150405", testTimeStr)
	expireTimeUnix := tim.Unix()
	returnURI := "http://local.example.com/return?name=wonk&id=wonk"
	token, err := mjwt.GenerateAccessToken(tokenSecret, userID, expireTimeUnix, returnURI)
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	fmt.Println(token)

	expected := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NDEwMzg1ODMsInJldHVybl91cmkiOiJodHRwOi8vbG9jYWwuZXhhbXBsZS5jb20vcmV0dXJuP25hbWU9d29ua1x1MDAyNmlkPXdvbmsiLCJ1c3JfaWQiOiJ3b25rIn0.Mxm4Hq60W2iL5QT2ORj8UMA40fsbiXFTw-IuCoypPuA"
	assert.Equal(t, expected, token)
}

func TestValidateAccessToken(t *testing.T) {
	tokenSecret := "asdfasdf1234"
	userID := "wonk"
	returnURI := "http://local.example.com/return?name=wonk&id=wonk"
	accessToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NDEwMzg1ODMsInJldHVybl91cmkiOiJodHRwOi8vbG9jYWwuZXhhbXBsZS5jb20vcmV0dXJuP25hbWU9d29ua1x1MDAyNmlkPXdvbmsiLCJ1c3JfaWQiOiJ3b25rIn0.Mxm4Hq60W2iL5QT2ORj8UMA40fsbiXFTw-IuCoypPuA"
	claim, _, err := mjwt.ValidateAccessToken(accessToken, tokenSecret)
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	assert.Equal(t, userID, claim.UsrID)
	assert.Equal(t, returnURI, claim.ReturnURI)
}
