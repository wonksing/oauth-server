# OAuth Server

## Go Get
- `go get`으로 의존 패키지 설치하기
```bash
go get github.com/dgrijalva/jwt-go
go get -u -v github.com/go-oauth2/oauth2/v4/...
```


http://172.16.120.174:9096/oauth/authorize?client_id=12345&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8%3D&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A9094%2Foauth2&response_type=code&scope=all&state=xyz