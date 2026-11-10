# authkit

hwan 体系的认证公共库（Go module：`github.com/hwanyan/authkit`）。**不是一个运行的服务**，只是被编译进各使用方的代码。

目前包含：

| 包 | 作用 |
|---|---|
| `verifier` | Access Token（JWT，EdDSA/Ed25519）的本地验签：公钥缓存、`kid` 轮换时按需重新拉取、严格的 `Parse` 规则 |

## 为什么单独成库

Access Token 由 auth 服务签发，由 agently、agenteam 等业务服务在**本地**验签（不回源、不查库）。
签发方与验签方必须使用同一套解析规则（只允许 EdDSA、强制 `exp` / `iss` / `aud`、要求 `sub` 与 `family_id`），
放在同一个库里维护，才不会出现规则漂移，安全修复也只需要改一处。

使用方：

- `hwan/app/auth`：签发与登出时用 `verifier.Parse` 解析 Token
- `agently`、`agenteam`：用 `verifier.New(...).Verify(...)` 做请求入口验签

## 用法

```go
import "github.com/hwanyan/authkit/verifier"

// conn 是到 auth 服务的 gRPC 连接，已携带服务凭证；这里不会立即拉取公钥
v := verifier.New(authpb.NewAuthServiceClient(conn))

claims, err := v.Verify(ctx, bearerToken) // 本地验签：签名、exp、iss、aud；公钥取自 auth 的 GetJWKS 并缓存
switch {
case errors.Is(err, verifier.ErrInvalidToken):     // 401：Token 无效 / 过期 / 受众不符
case errors.Is(err, verifier.ErrKeysUnavailable):  // 503：取不到公钥（auth 不可达且无缓存），不要当成 401，否则会把用户踢下线
}
```

`audience` 与 `issuer` 不需要使用方配置：它们来自 auth 的 `GetJWKS` 响应，auth 按调用方的服务凭证返回各自的受众。

## 依赖

只依赖 `github.com/hwanyan/proto`（auth 的 gRPC 契约）、`golang-jwt/jwt/v5` 与 `google.golang.org/grpc`，
不依赖 `hwan` 主仓库。

## 开发与发版

```bash
go vet ./... && go test -race ./...
```

发版：打 tag（如 `v0.1.0`）并推送；各使用方分别执行 `go get github.com/hwanyan/authkit@<tag>` 升级。
**升级不是自动的**——涉及安全修复时，发版后要确认所有使用方都已升级。

本地联调（尚未发版或同时修改多个项目时），在使用方的 `go.mod` 中临时加：

```
replace github.com/hwanyan/authkit => ../authkit
```

发版后记得删掉。注意：`replace` 只对当前 module 生效，不会传递给依赖它的项目。
