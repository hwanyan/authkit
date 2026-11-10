package verifier

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	authpb "github.com/hwanyan/proto/auth"
	"google.golang.org/grpc"
)

// KeySource 公钥来源。authpb.AuthServiceClient 天然满足该接口。
type KeySource interface {
	GetJWKS(ctx context.Context, in *authpb.GetJWKSRequest, opts ...grpc.CallOption) (*authpb.GetJWKSResponse, error)
}

const (
	defaultKeyTTL     = 10 * time.Minute // 公钥缓存时长：到期后在下一次验签时顺带刷新
	defaultMinRefetch = 10 * time.Second // 两次拉取之间的最小间隔，防止未知 kid 的垃圾 Token 打爆认证服务
	fetchTimeout      = 5 * time.Second
)

// Verifier 从认证服务拉取公钥并在本地验证 Access Token。
//
// 公钥缓存策略：
//   - 首次验签时拉取；之后每 keyTTL 刷新一次（刷新失败则继续使用旧缓存，不影响已登录用户）；
//   - Token 的 kid 不在缓存中（认证服务刚轮换了签名密钥）时立即重新拉取一次，受 minRefetch 限流；
//   - 缓存为空且拉取失败时返回 ErrKeysUnavailable。
//
// 验签是纯本地计算：不查库、不查 Redis、不回源认证服务（除拉取公钥外）。
// 因此用户登出后，已签发的 Access Token 在自然过期前（最长 access_ttl）仍能通过验签，这是无状态 JWT 的固有边界；
// 登出只吊销 Refresh Token，使其无法再续期。敏感操作应再调用 VerifyToken RPC 做强校验。
type Verifier struct {
	src        KeySource
	keyTTL     time.Duration
	minRefetch time.Duration
	now        func() time.Time

	fetchMu sync.Mutex // 串行化拉取，避免并发请求同时打到认证服务

	mu          sync.RWMutex
	keys        map[string]ed25519.PublicKey
	issuer      string
	audience    string
	fetchedAt   time.Time // 上一次成功拉取
	attemptedAt time.Time // 上一次尝试拉取（无论成败）
}

// Option 构造选项
type Option func(*Verifier)

// WithKeyTTL 设置公钥缓存时长
func WithKeyTTL(d time.Duration) Option { return func(v *Verifier) { v.keyTTL = d } }

// WithMinRefetch 设置两次拉取之间的最小间隔
func WithMinRefetch(d time.Duration) Option { return func(v *Verifier) { v.minRefetch = d } }

// New 创建验签器。不会立即拉取公钥（认证服务暂时不可用不应阻塞业务服务启动），首次验签时惰性拉取。
func New(src KeySource, opts ...Option) *Verifier {
	v := &Verifier{
		src:        src,
		keyTTL:     defaultKeyTTL,
		minRefetch: defaultMinRefetch,
		now:        time.Now,
		keys:       map[string]ed25519.PublicKey{},
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify 本地校验 Access Token（签名、过期、iss、aud）。不回源认证服务、不查库。
// 返回 ErrInvalidToken（Token 无效，应 401）或 ErrKeysUnavailable（取不到公钥，应 503）。
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	if err := v.ensureFresh(ctx); err != nil {
		return nil, err
	}

	v.mu.RLock()
	issuer, audience := v.issuer, v.audience
	v.mu.RUnlock()

	return Parse(token, func(kid string) (ed25519.PublicKey, error) {
		if k, ok := v.lookup(kid); ok {
			return k, nil
		}
		// 未知 kid：可能是认证服务刚轮换了密钥，立即（限流地）重新拉取一次
		if err := v.refetch(ctx, true); err != nil && !v.hasKeys() {
			return nil, err
		}
		if k, ok := v.lookup(kid); ok {
			return k, nil
		}
		return nil, errUnknownKey
	}, ParseOptions{Issuer: issuer, Audience: audience})
}

func (v *Verifier) lookup(kid string) (ed25519.PublicKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	k, ok := v.keys[kid]
	return k, ok
}

func (v *Verifier) hasKeys() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.keys) > 0
}

// ensureFresh 保证缓存可用：为空时必须拉取成功；过期时尽力刷新，失败沿用旧缓存。
func (v *Verifier) ensureFresh(ctx context.Context) error {
	v.mu.RLock()
	empty := len(v.keys) == 0
	stale := v.now().Sub(v.fetchedAt) > v.keyTTL
	v.mu.RUnlock()

	switch {
	case empty:
		return v.refetch(ctx, false)
	case stale:
		if err := v.refetch(ctx, true); err != nil {
			log.Printf("authkit/verifier: 刷新公钥失败，继续使用缓存: %v", err)
		}
	}
	return nil
}

// refetch 从认证服务拉取公钥。throttled 为 true 时，距上次尝试不足 minRefetch 则直接跳过（视为成功）。
func (v *Verifier) refetch(ctx context.Context, throttled bool) error {
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()

	v.mu.RLock()
	last, hasKeys := v.attemptedAt, len(v.keys) > 0
	v.mu.RUnlock()
	// 其它协程可能刚刚拉取过：缓存非空且在限流窗口内就不再重复拉取
	if throttled && hasKeys && v.now().Sub(last) < v.minRefetch {
		return nil
	}

	v.mu.Lock()
	v.attemptedAt = v.now()
	v.mu.Unlock()

	callCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	resp, err := v.src.GetJWKS(callCtx, &authpb.GetJWKSRequest{})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeysUnavailable, err)
	}

	keys := make(map[string]ed25519.PublicKey, len(resp.GetKeys()))
	for _, k := range resp.GetKeys() {
		pub, err := decodeJWK(k)
		if err != nil {
			log.Printf("authkit/verifier: 忽略无法识别的公钥 kid=%q: %v", k.GetKid(), err)
			continue
		}
		keys[k.GetKid()] = pub
	}
	if len(keys) == 0 || resp.GetIssuer() == "" || resp.GetAudience() == "" {
		return fmt.Errorf("%w: 认证服务返回的 JWKS 不可用", ErrKeysUnavailable)
	}

	v.mu.Lock()
	v.keys, v.issuer, v.audience, v.fetchedAt = keys, resp.GetIssuer(), resp.GetAudience(), v.now()
	v.mu.Unlock()
	return nil
}

// decodeJWK 解析一把 Ed25519 公钥（kty=OKP, crv=Ed25519, alg=EdDSA）
func decodeJWK(k *authpb.Jwk) (ed25519.PublicKey, error) {
	if k.GetKid() == "" {
		return nil, errors.New("缺少 kid")
	}
	if k.GetKty() != "OKP" || k.GetCrv() != "Ed25519" || k.GetAlg() != SigningAlg {
		return nil, fmt.Errorf("不支持的密钥类型 kty=%s crv=%s alg=%s", k.GetKty(), k.GetCrv(), k.GetAlg())
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.GetX())
	if err != nil {
		return nil, fmt.Errorf("x 不是合法的 base64url: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("公钥长度应为 %d 字节，实际 %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
