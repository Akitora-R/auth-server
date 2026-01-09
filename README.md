# Description

🐯 Simple OAuth 2.0 Authorization Server Implementation In Go

# Flow

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant C as Client App Server
    participant A as Authorisation Server
    participant R as Resource Server

    %% 1. 用户发起请求
    B->>C: Request Service
    activate C
    
    %% 2. 客户端重定向用户到认证服务器
    Note right of B: Redirect URI
    C-->>B: Redirect with Auth. code request
    deactivate C
    
    %% 3. 浏览器向认证服务器发起认证请求
    B->>A: GET Authorisation endpoint
    activate A
    Note right of B: Params: client_id, response_type=code,<br/>scope, redirect_URI, state,<br/>(code_challenge, nonce)

    %% 4. 用户登录与授权交互
    A->>B: User Authentication (Login)
    B-->>A: User Credentials
    A->>B: User Authorisation (Consent)
    B-->>A: User Consents

    %% 5. 认证服务器颁发授权码并重定向回客户端
    Note right of A: Check redirect_uri matches<br/>approved callback url
    A-->>B: Redirect with Auth Code
    deactivate A

    %% 6. 浏览器携带授权码回调客户端
    B->>C: GET Callback URL
    activate C
    Note right of B: Params: Authorisation Code, state

    %% 7. 客户端使用授权码换取 Access Token
    C->>A: POST Access Token Req. (Token endpoint)
    activate A
    Note left of A: Params: client_id, client_secret,<br/>auth code, grant_type=authorization_code,<br/>redirect_URI, (code_verifier)

    Note right of A: Validate client & code,<br/>Verify redirect_uri,<br/>Issue token(s)

    A-->>C: Access Token Response
    deactivate A
    Note right of C: Body: Access token,<br/>refresh token,<br/>id token, scope

    %% 8. 客户端使用 Token 请求资源
    C->>R: Use APIs (with Token)
    activate R
    R-->>C: API Response
    deactivate R

    %% 9. 响应用户
    C-->>B: Provide Service
    deactivate C
```

# config.yaml

```yaml
port: 80
host: 0.0.0.0
redis:
  address: 127.0.0.1:6379
db: "root:root@(localhost:3306)/auth?parseTime=true"
jwt:
  - kid: "rsa1"
    alg: "RS256"
    sec: |
      -----BEGIN RSA PRIVATE KEY-----
      ...
      -----END RSA PRIVATE KEY-----
```
