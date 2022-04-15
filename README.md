OAuth Server Demo

* 로그인 요청 (authorization_code)
  - http://localhost:8080/oauth/authorize?client_id=testapp&redirect_uri=http://localhost:8080/oauth2/callback&response_type=code&scope=read
* 토큰키 요청 (password 타입)
  - curl testapp:123456@localhost:8080/oauth/token -dgrant_type=password -dscope=read -d username=test0001@gmail.com -d password=abcd1234 