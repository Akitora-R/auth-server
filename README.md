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
  host: 0.0.0.0
  port: 6379
db: "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable&search_path=auth"
jwt:
  - kid: "rsa1"
    alg: "RS256"
    sec: |
      -----BEGIN RSA PRIVATE KEY-----
      ...
      -----END RSA PRIVATE KEY-----
```

## 🗺️ TODO

### Phase 1: 核心身份与授权机制 (IdP Core)
- [ ] **精简内部权限模型**：新增表 `auth_admin` 记录管理员用户。通过 `user_id` 字段关联到 `auth_user` 表，表中存在记录即标记该用户具备管理员权限。
- [ ] **注册第一方客户端**：在系统初始化时，自动注入一个内置的管理员客户端（例如 `client_id=internal_admin_console`）。
- [ ] **定义特权 Scope**：明确界定后台管理专用的作用域（如 `manage:system`, `manage:clients`），并在颁发 Token 时结合用户内置身份进行严格校验。

### Phase 2: 资源服务器隔离 (Admin API)
- [ ] **路由组切割**：独立划分 `/api/admin/*` 路由组，专门用于处理后台管理的数据交互。
- [ ] **特权鉴权中间件**：实现无状态的 JWT 校验拦截器。该中间件强制要求：
  - Token 必须由合法的 `internal_admin_console` 客户端申请。
  - Token 必须包含对应的高级 `scope`。
  - Token 对应的底层 `User` 必须在 `auth_admin` 表中存在记录。

### Phase 3: 轻量级管理前端客户端 (Admin UI Client)
- [ ] **极简 SPA 开发**：摒弃重型前端脚手架，使用原生 HTML/JS/CSS（或轻量级 CDN 框架如 Alpine.js/htmx）构建单页管理应用。功能涵盖：
  - **用户管理**：列表查询、创建/编辑、启用/禁用、密码重置。
  - **客户端管理**：注册/编辑 OAuth2 客户端（client_id, redirect_uri, grant_types）、分配允许的 Scope、启停客户端。
  - **会话管理**：查看活跃 Token/会话列表、强制撤销/下线。
  - **管理员管理**：查看/添加/移除 `auth_admin` 表中的管理员记录。
- [ ] **静态资源内嵌**：利用 Go `embed` 特性，将前端文件无缝打包至编译后的单个二进制文件中，实现零额外依赖部署。
- [ ] **宿主路由分发**：开放 `/admin-page` 路由，作为静态文件的宿主，直接吐出前端页面。

### Phase 4: 标准化安全集成 (Security & Integration)
- [ ] **PKCE 授权码流程**：在纯前端 SPA 中实现 Authorization Code Flow with PKCE，安全地获取 Access Token（无需后端 Client Secret）。
- [ ] **无缝联调**：实现未登录时的自动拦截，引导跳转至本地 `/oauth2/authorize` 页面，完成闭环体验。