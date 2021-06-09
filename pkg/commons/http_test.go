package commons_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/wonksing/oauth-server/pkg/commons"
)

func TestSetCookie(t *testing.T) {
	w := httptest.NewRecorder()

	commons.SetCookie(w, "test_cookie_key", "test_cookie_value", time.Duration(2))

	c := w.Result().Cookies()
	if !assert.NotNil(t, c) {
		t.FailNow()
	}

	if !assert.Equal(t, "test_cookie_value", c[0].Value) {
		t.FailNow()
	}
}
