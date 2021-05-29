# OAuth Server

## Go Get
- `go get`으로 의존 패키지 설치하기
```bash
go get github.com/dgrijalva/jwt-go
go get -u -v github.com/go-oauth2/oauth2/v4/...
go get -u github.com/gorilla/mux
go get -u github.com/gorilla/handlers
```


http://localhost:9096/oauth/authorize?client_id=12345&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8%3D&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A9094%2Foauth2&response_type=code&scope=all&state=xyz

curl \
-X GET \
'http://127.0.0.1:9096/oauth/token/_validate?access_token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMjM0NSIsImV4cCI6MTYyMjEzNzAxNX0.U500AokK3e0jt4CATXKTOu4WdX6VXLw9xYRbAxtPbeJRJahiynwx29pMlNDkCXDXFsceoVKswWCruEVaEstXTQ'


curl \
-X GET \
'http://127.0.0.1:9096/oauth/token/_validate?access_token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMjM0NSIsImV4cCI6MTYyMjEzNzA0OCwic3ViIjoiYXNkZiJ9.OYmeOjkQXTd75A1XhgzS9afqYZhg2zng_kD55hOR4fKNi9oBaLFBcRDHwmQeuASVZuWQHKqp2nIq1PXg5IE3Hg'