package merror_test

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wonksing/oauth-server/pkg/models/merror"
)

func TestOAuthError(t *testing.T) {
	err := merror.NewOAuthError("1000", "error test", http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
	assert.Equal(t, "(1000)error test", err.Error())
}

func TestOAuthErrorResponseData(t *testing.T) {
	expected := make(map[string]interface{})
	expected["error"] = http.StatusText(http.StatusBadRequest)
	expected["error_description"] = "error test"

	err := merror.NewOAuthError("1000", "error test", http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
	data := err.(*merror.OAuthError).ResponseData()
	assert.Equal(t, expected, data)
}

type testResponseWriter struct {
	buf bytes.Buffer
}

func NewTestResponseWriter() http.ResponseWriter {
	return &testResponseWriter{
		buf: bytes.Buffer{},
	}
}
func (o *testResponseWriter) Header() http.Header {
	return nil
}
func (o *testResponseWriter) Write(b []byte) (int, error) {
	return o.buf.Write(b)
}
func (o *testResponseWriter) WriteHeader(statusCode int) {

}
func (o *testResponseWriter) String() string {
	return o.buf.String()
}
func TestHttpRespond(t *testing.T) {
	w := NewTestResponseWriter()
	merror.HttpRespond(w, http.StatusBadRequest, merror.ErrorInsufficientClientInfo)
	expected := `{"error":"Bad Request","error_description":"requested client info is insufficient"}`
	expected = fmt.Sprintf("%s\n", expected)
	assert.Equal(t, expected, w.(*testResponseWriter).String())
}

func TestHttpError(t *testing.T) {
	var err error

	err = merror.ErrorNoAllowedResource
	switch err := err.(type) {
	case *merror.OAuthError:
		data := err.ResponseData()
		fmt.Println("oautherror", data)
	default:
		data := make(map[string]interface{})
		data["error"] = http.StatusText(http.StatusBadRequest)
		data["error_description"] = err.Error()
		fmt.Println("default", data)
	}
}
