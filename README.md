# Description

🐯 Simple OAuth 2.0 Authorization Server Implementation In Go

# Flow

![flow.png](flow.png)

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
