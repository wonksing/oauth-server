# OAuth Server

## Go Get
- `go get`으로 의존 패키지 설치하기
```bash
go get github.com/dgrijalva/jwt-go
go get -u -v github.com/go-oauth2/oauth2/v4/...
go get -u github.com/gorilla/mux
go get -u github.com/gorilla/handlers

go get -u github.com/natefinch/lumberjack
go get -u github.com/sirupsen/logrus

go get golang.org/x/oauth2

go get -u github.com/stretchr/testify

go get github.com/golang/mock/mockgen@v1.5.0
go install github.com/golang/mock/mockgen@v1.5.0
```

## Scripts
```bash
curl \
-X GET \
-H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMjM0NSIsImV4cCI6MTYyMzU0OTY5NCwic3ViIjoiYXNkZiIsIlNjb3BlIjoiYWxsIn0.PWdcUUA2CfdARC34hTgDkAh-jsxd9WBZl6phuPAWvrh-EGiRewZ4BYAor7_D8_ezcJzRO7wbxEcR1TtJpFfQkw' \
'http://localhost:9099/oauth/protected'
```

```bash
curl \
-X GET \
-H 'Authorization: Basic YWJjZGU6YWJjZDEyMzQ=' \
'http://localhost:9096/oauth/token?grant_type=client_credentials&scope=item emp'

{"access_token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhYmNkZSIsImV4cCI6MTYyMzU5Nzk3NCwic2NvcGUiOiJhbGwifQ.ba_Aj5_cYEd4SeZVM5M9F02PISILXLV0BZxR9IR-ndo_rT11etUa1Clg7Erl4gFrqvHrDy2LBfMwonRcvZvJFg","expires_in":7200,"scope":"all","token_type":"Bearer"}

curl \
-X GET \
-H 'Authorization: Basic YWJjZGU6YWJjZDEyMzQ=' \
-G "http://localhost:9096/oauth/token" \
--data-urlencode "grant_type=client_credentials" \
--data-urlencode "scope=item emp" 
```

http://localhost:9096/oauth/authorize?client_id=12345&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8%3D&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A9094%2Foauth2&response_type=code&scope=all&state=xyz

curl \
-X GET \
'http://127.0.0.1:9096/oauth/token/_validate?access_token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMjM0NSIsImV4cCI6MTYyMjEzNzAxNX0.U500AokK3e0jt4CATXKTOu4WdX6VXLw9xYRbAxtPbeJRJahiynwx29pMlNDkCXDXFsceoVKswWCruEVaEstXTQ'


curl \
-X GET \
'http://127.0.0.1:9096/oauth/token/_validate?access_token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMjM0NSIsImV4cCI6MTYyMjEzNzA0OCwic3ViIjoiYXNkZiJ9.OYmeOjkQXTd75A1XhgzS9afqYZhg2zng_kD55hOR4fKNi9oBaLFBcRDHwmQeuASVZuWQHKqp2nIq1PXg5IE3Hg'