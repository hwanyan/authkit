// Package verifier 是「Access Token 本地验签」SDK。
//
// 它由 auth 服务（签发方）与各业务服务（验签方，如 agently、agenteam）共同依赖：
// auth 签发 / 校验 Token 时用的也是同一份校验逻辑（见 Parse），签发方与验签方的规则不可能不一致。
//
// 业务服务的用法：
//
//	v := verifier.New(authpb.NewAuthServiceClient(conn))   // conn 已携带服务凭证
//	claims, err := v.Verify(ctx, bearerToken)               // 本地验签，不回源、不查库
package verifier

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SigningAlg Access Token 的签名算法（Ed25519）
const SigningAlg = "EdDSA"

var (
	// ErrInvalidToken Token 无效：格式错误、签名不符、已过期、iss/aud 不匹配、算法不允许等
	ErrInvalidToken = errors.New("invalid token")
	// ErrKeysUnavailable 无法取得验签公钥（认证服务不可达且本地没有缓存）。
	// 与 ErrInvalidToken 严格区分：这是服务端的问题，调用方应返回 503 而不是 401，避免把用户踢下线。
	ErrKeysUnavailable = errors.New("verification keys unavailable")
	// errUnknownKey Token 头部的 kid 不在已知公钥中
	errUnknownKey = errors.New("unknown key id")
)

// Claims Access Token 载荷
type Claims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles,omitempty"`
	// FamilyID 登录链路 ID：同一次登录换出的所有 Refresh Token 共享，对应 refresh_tokens.family_id。
	// 登出时据此吊销整条链路的 Refresh Token。
	FamilyID string `json:"family_id"`
	jwt.RegisteredClaims
}

// UserID 用户 ID（即 sub）
func (c *Claims) UserID() string { return c.Subject }

// HasRole 是否拥有指定平台级角色
func (c *Claims) HasRole(role string) bool { return slices.Contains(c.Roles, role) }

// KeyFunc 按 kid 返回验签公钥；kid 未知时应返回 errUnknownKey 一类的错误
type KeyFunc func(kid string) (ed25519.PublicKey, error)

// ParseOptions 校验选项
type ParseOptions struct {
	Issuer   string // 必填
	Audience string // 必填
	// IgnoreExpiry 为 true 时不校验 exp（签名、iss、aud 仍然严格校验）。
	// 仅用于「登出」：Access Token 过期后用户仍应能吊销自己的登录链路。
	IgnoreExpiry bool
	// Leeway 允许的时钟偏差，默认 5 秒
	Leeway time.Duration
}

// Parse 校验 Access Token 并返回载荷。
//
// 安全要点：
//   - 只允许 EdDSA：拒绝 alg=none，也拒绝把公钥当 HMAC 密钥的「算法混淆」攻击；
//   - 必须有 exp（除非 IgnoreExpiry）、sub、family_id；
//   - iss / aud 必须与期望值一致。
//
// 所有 Token 本身的问题统一返回 ErrInvalidToken（可 errors.Is 判断）；
// keyFn 返回的 ErrKeysUnavailable 会原样保留。
func Parse(tokenStr string, keyFn KeyFunc, opt ParseOptions) (*Claims, error) {
	if opt.Issuer == "" || opt.Audience == "" {
		return nil, errors.New("authkit/verifier: Issuer 与 Audience 不能为空")
	}
	leeway := opt.Leeway
	if leeway <= 0 {
		leeway = 5 * time.Second
	}

	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{SigningAlg}),
		jwt.WithLeeway(leeway),
	}
	if opt.IgnoreExpiry {
		parserOpts = append(parserOpts, jwt.WithoutClaimsValidation())
	} else {
		parserOpts = append(parserOpts, jwt.WithExpirationRequired())
	}

	claims := &Claims{}
	tok, err := jwt.NewParser(parserOpts...).ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errUnknownKey
		}
		return keyFn(kid)
	})
	if err != nil {
		if errors.Is(err, ErrKeysUnavailable) {
			return nil, ErrKeysUnavailable
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !tok.Valid {
		return nil, ErrInvalidToken
	}

	if claims.Issuer != opt.Issuer {
		return nil, fmt.Errorf("%w: issuer 不匹配", ErrInvalidToken)
	}
	if !slices.Contains(claims.Audience, opt.Audience) {
		return nil, fmt.Errorf("%w: audience 不匹配", ErrInvalidToken)
	}
	if claims.Subject == "" || claims.FamilyID == "" {
		return nil, fmt.Errorf("%w: 缺少 sub 或 family_id", ErrInvalidToken)
	}
	return claims, nil
}
