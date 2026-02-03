package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/adeilh/go-rakh/cache"
)

var (
	ErrJWTInvalidFormat     = errors.New("auth: invalid jwt format")
	ErrJWTInvalidSignature  = errors.New("auth: invalid jwt signature")
	ErrJWTUnsupportedAlgo   = errors.New("auth: unsupported jwt algorithm")
	ErrJWTExpired           = errors.New("auth: jwt expired")
	ErrJWTNotYetValid       = errors.New("auth: jwt not yet valid")
	ErrJWTRevoked           = errors.New("auth: jwt revoked")
	ErrJWTInvalidClaims     = errors.New("auth: invalid jwt claims")
	ErrJWTMissingSigningKey = errors.New("auth: missing signing key")
	ErrJWTWeakSigningKey    = errors.New("auth: signing key too short")
	ErrJWTInvalidIssuer     = errors.New("auth: invalid jwt issuer")
	ErrJWTInvalidAudience   = errors.New("auth: invalid jwt audience")
)

// MinSecretLength is the minimum recommended secret length for HMAC-SHA256
const MinSecretLength = 32

const defaultJWTCachePrefix = "jwt"

type jwtToken struct {
	raw    string
	claims JWTClaims
}

func (t jwtToken) Raw() string { return t.raw }

func (t jwtToken) Claims() JWTClaims { return t.claims }

func (t jwtToken) IssuedAt() time.Time { return t.claims.IssuedAt }

func (t jwtToken) ExpiresAt() time.Time { return t.claims.ExpiresAt }

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}

type jwtPayload struct {
	ID        string         `json:"jti,omitempty"`
	Subject   string         `json:"sub,omitempty"`
	Issuer    string         `json:"iss,omitempty"`
	Audience  []string       `json:"aud,omitempty"`
	IssuedAt  int64          `json:"iat,omitempty"`
	ExpiresAt int64          `json:"exp,omitempty"`
	NotBefore int64          `json:"nbf,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// HMACJWTProvider implements JWTTokenProvider using HMAC signing.
type HMACJWTProvider struct {
	secret           []byte
	allowedAlgs      map[string]struct{}
	defaultAlg       string
	leeway           time.Duration
	now              func() time.Time
	revoked          sync.Map
	store            cache.Store
	cachePrefix      string
	requiredIssuer   string
	requiredAudience []string
	enforceSecretLen bool
}

// NewHMACJWTProvider creates an HMAC based JWT provider that only relies on the
// standard library. Algorithms defaults to HS256 when none are supplied.
// For production use, secrets should be at least 32 bytes (256 bits).
func NewHMACJWTProvider(secret []byte, algorithms ...string) (*HMACJWTProvider, error) {
	if len(secret) == 0 {
		return nil, ErrJWTMissingSigningKey
	}
	if len(algorithms) == 0 {
		algorithms = []string{"HS256"}
	}

	allowed := make(map[string]struct{}, len(algorithms))
	for _, alg := range algorithms {
		if _, err := signingHasher(alg); err != nil {
			return nil, err
		}
		allowed[alg] = struct{}{}
	}

	return &HMACJWTProvider{
		secret:           append([]byte(nil), secret...),
		allowedAlgs:      allowed,
		defaultAlg:       algorithms[0],
		leeway:           30 * time.Second,
		now:              time.Now,
		cachePrefix:      defaultJWTCachePrefix,
		enforceSecretLen: false,
	}, nil
}

// NewSecureHMACJWTProvider creates an HMAC based JWT provider with enforced security.
// It requires a minimum secret length of 32 bytes for HS256, 48 for HS384, 64 for HS512.
func NewSecureHMACJWTProvider(secret []byte, algorithms ...string) (*HMACJWTProvider, error) {
	if len(algorithms) == 0 {
		algorithms = []string{"HS256"}
	}

	// Determine minimum required secret length based on algorithm
	minLen := MinSecretLength
	for _, alg := range algorithms {
		switch alg {
		case "HS384":
			if minLen < 48 {
				minLen = 48
			}
		case "HS512":
			if minLen < 64 {
				minLen = 64
			}
		}
	}

	if len(secret) < minLen {
		return nil, fmt.Errorf("%w: need at least %d bytes", ErrJWTWeakSigningKey, minLen)
	}

	provider, err := NewHMACJWTProvider(secret, algorithms...)
	if err != nil {
		return nil, err
	}
	provider.enforceSecretLen = true
	return provider, nil
}

// SetRequiredIssuer enforces issuer validation during token parsing.
func (p *HMACJWTProvider) SetRequiredIssuer(issuer string) {
	p.requiredIssuer = issuer
}

// SetRequiredAudience enforces audience validation during token parsing.
func (p *HMACJWTProvider) SetRequiredAudience(audience ...string) {
	p.requiredAudience = cloneStrings(audience)
}

// SetLeeway overrides the default expiration leeway used during validation.
func (p *HMACJWTProvider) SetLeeway(d time.Duration) {
	if d < 0 {
		d = 0
	}
	p.leeway = d
}

// SetNowFunc allows injecting a deterministic clock (useful for tests).
func (p *HMACJWTProvider) SetNowFunc(fn func() time.Time) {
	if fn == nil {
		fn = time.Now
	}
	p.now = fn
}

// UseCache injects a cache.Store for persisting issued JWTs.
func (p *HMACJWTProvider) UseCache(store cache.Store) {
	p.store = store
	if p.cachePrefix == "" {
		p.cachePrefix = defaultJWTCachePrefix
	}
}

// SetCachePrefix customizes the cache namespace used for JWT keys.
func (p *HMACJWTProvider) SetCachePrefix(prefix string) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = defaultJWTCachePrefix
	}
	p.cachePrefix = prefix
}

func (p *HMACJWTProvider) Issue(ctx context.Context, claims JWTClaims, opts JWTOptions) (JWTToken, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}

	alg, err := p.resolveAlgorithm(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	prepared, err := p.prepareClaims(claims, opts)
	if err != nil {
		return nil, err
	}

	header := jwtHeader{Algorithm: alg, Type: "JWT", KeyID: opts.KeyID}
	headerSeg, err := encodeSegment(header)
	if err != nil {
		return nil, err
	}

	payloadSeg, err := encodeSegment(payloadFromClaims(prepared))
	if err != nil {
		return nil, err
	}

	signingInput := headerSeg + "." + payloadSeg
	signatureSeg, err := p.sign(signingInput, alg)
	if err != nil {
		return nil, err
	}

	token := &jwtToken{
		raw:    signingInput + "." + signatureSeg,
		claims: prepared,
	}

	if err := p.persistToken(ctx, token); err != nil {
		return nil, err
	}

	return token, nil
}

func (p *HMACJWTProvider) Parse(ctx context.Context, raw string) (JWTToken, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrJWTInvalidFormat
	}

	var header jwtHeader
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, ErrJWTInvalidFormat
	}

	if err := p.verify(parts[0]+"."+parts[1], parts[2], header.Algorithm); err != nil {
		return nil, err
	}

	var payload jwtPayload
	if err := decodeSegment(parts[1], &payload); err != nil {
		return nil, ErrJWTInvalidFormat
	}

	claims := claimsFromPayload(payload)
	if err := p.validateClaims(claims); err != nil {
		return nil, err
	}

	if err := p.ensureCached(ctx, claims.ID); err != nil {
		return nil, err
	}

	if _, revoked := p.revoked.Load(claims.ID); revoked {
		return nil, ErrJWTRevoked
	}

	return &jwtToken{raw: raw, claims: claims}, nil
}

func (p *HMACJWTProvider) Revoke(ctx context.Context, tokenID string) error {
	if tokenID == "" {
		return fmt.Errorf("%w: empty token id", ErrJWTInvalidClaims)
	}
	p.revoked.Store(tokenID, struct{}{})
	if err := p.evictCache(ctx, tokenID); err != nil {
		return err
	}
	return nil
}

func (p *HMACJWTProvider) prepareClaims(claims JWTClaims, opts JWTOptions) (JWTClaims, error) {
	c := claims
	c.Audience = cloneStrings(claims.Audience)
	c.Metadata = cloneMetadata(claims.Metadata)

	now := p.now()
	if c.ID == "" {
		id, err := randomID()
		if err != nil {
			return JWTClaims{}, err
		}
		c.ID = id
	}

	if c.IssuedAt.IsZero() {
		c.IssuedAt = now
	}

	if c.ExpiresAt.IsZero() && opts.TTL > 0 {
		c.ExpiresAt = c.IssuedAt.Add(opts.TTL)
	} else if opts.TTL < 0 {
		return JWTClaims{}, fmt.Errorf("%w: negative ttl", ErrJWTInvalidClaims)
	}

	if c.NotBefore.IsZero() {
		if opts.ClockSkew > 0 {
			c.NotBefore = c.IssuedAt.Add(-opts.ClockSkew)
		} else {
			c.NotBefore = c.IssuedAt
		}
	}

	if !c.ExpiresAt.IsZero() && c.ExpiresAt.Before(c.IssuedAt) {
		return JWTClaims{}, fmt.Errorf("%w: expires before issued", ErrJWTInvalidClaims)
	}

	if c.Issuer == "" {
		c.Issuer = opts.Issuer
	}

	if len(c.Audience) == 0 && len(opts.Audience) > 0 {
		c.Audience = cloneStrings(opts.Audience)
	}

	return c, nil
}

func (p *HMACJWTProvider) validateClaims(claims JWTClaims) error {
	now := p.now()

	if !claims.ExpiresAt.IsZero() && now.After(claims.ExpiresAt.Add(p.leeway)) {
		return ErrJWTExpired
	}

	if !claims.NotBefore.IsZero() && now.Add(p.leeway).Before(claims.NotBefore) {
		return ErrJWTNotYetValid
	}

	// Validate required issuer if configured
	if p.requiredIssuer != "" && claims.Issuer != p.requiredIssuer {
		return ErrJWTInvalidIssuer
	}

	// Validate required audience if configured
	if len(p.requiredAudience) > 0 {
		if !hasAudienceMatch(claims.Audience, p.requiredAudience) {
			return ErrJWTInvalidAudience
		}
	}

	return nil
}

// hasAudienceMatch checks if at least one of the required audiences is present in the token
func hasAudienceMatch(tokenAud, requiredAud []string) bool {
	if len(tokenAud) == 0 || len(requiredAud) == 0 {
		return false
	}
	audSet := make(map[string]struct{}, len(tokenAud))
	for _, a := range tokenAud {
		audSet[a] = struct{}{}
	}
	for _, req := range requiredAud {
		if _, ok := audSet[req]; ok {
			return true
		}
	}
	return false
}

func (p *HMACJWTProvider) resolveAlgorithm(requested string) (string, error) {
	alg := requested
	if alg == "" {
		alg = p.defaultAlg
	}
	if _, ok := p.allowedAlgs[alg]; !ok {
		return "", ErrJWTUnsupportedAlgo
	}
	return alg, nil
}

func (p *HMACJWTProvider) sign(input, alg string) (string, error) {
	hasher, err := signingHasher(alg)
	if err != nil {
		return "", err
	}
	mac := hmac.New(hasher, p.secret)
	_, _ = mac.Write([]byte(input))
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func (p *HMACJWTProvider) verify(input, signature, alg string) error {
	if _, ok := p.allowedAlgs[alg]; !ok {
		return ErrJWTUnsupportedAlgo
	}

	hasher, err := signingHasher(alg)
	if err != nil {
		return err
	}

	provided, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return ErrJWTInvalidSignature
	}

	mac := hmac.New(hasher, p.secret)
	_, _ = mac.Write([]byte(input))
	expected := mac.Sum(nil)
	if !hmac.Equal(provided, expected) {
		return ErrJWTInvalidSignature
	}

	return nil
}

func signingHasher(alg string) (func() hash.Hash, error) {
	switch alg {
	case "HS256":
		return sha256.New, nil
	case "HS384":
		return sha512.New384, nil
	case "HS512":
		return sha512.New, nil
	default:
		return nil, ErrJWTUnsupportedAlgo
	}
}

func (p *HMACJWTProvider) persistToken(ctx context.Context, token *jwtToken) error {
	if p.store == nil || token == nil {
		return nil
	}
	if token.claims.ID == "" {
		return ErrJWTInvalidClaims
	}
	ttl := p.tokenTTL(token.claims)
	if ttl <= 0 {
		return nil
	}
	return p.store.Set(ctx, p.cacheKey(token.claims.ID), []byte(token.raw), ttl)
}

func (p *HMACJWTProvider) ensureCached(ctx context.Context, tokenID string) error {
	if p.store == nil {
		return nil
	}
	if tokenID == "" {
		return ErrJWTInvalidClaims
	}
	_, err := p.store.Get(ctx, p.cacheKey(tokenID))
	if err == nil {
		return nil
	}
	if errors.Is(err, cache.ErrNotFound) {
		return ErrJWTRevoked
	}
	return err
}

func (p *HMACJWTProvider) evictCache(ctx context.Context, tokenID string) error {
	if p.store == nil {
		return nil
	}
	key := p.cacheKey(tokenID)
	err := p.store.Delete(ctx, key)
	if err != nil && !errors.Is(err, cache.ErrNotFound) {
		return err
	}
	return nil
}

func (p *HMACJWTProvider) tokenTTL(claims JWTClaims) time.Duration {
	if claims.ExpiresAt.IsZero() {
		return 0
	}
	ttl := claims.ExpiresAt.Sub(p.now())
	if ttl < 0 {
		return 0
	}
	return ttl
}

func (p *HMACJWTProvider) cacheKey(id string) string {
	prefix := p.cachePrefix
	if prefix == "" {
		prefix = defaultJWTCachePrefix
	}
	return prefix + ":" + id
}

func payloadFromClaims(claims JWTClaims) jwtPayload {
	return jwtPayload{
		ID:        claims.ID,
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  cloneStrings(claims.Audience),
		IssuedAt:  unixOrZero(claims.IssuedAt),
		ExpiresAt: unixOrZero(claims.ExpiresAt),
		NotBefore: unixOrZero(claims.NotBefore),
		Metadata:  cloneMetadata(claims.Metadata),
	}
}

func claimsFromPayload(payload jwtPayload) JWTClaims {
	return JWTClaims{
		ID:        payload.ID,
		Subject:   payload.Subject,
		Issuer:    payload.Issuer,
		Audience:  cloneStrings(payload.Audience),
		IssuedAt:  timeFromUnix(payload.IssuedAt),
		ExpiresAt: timeFromUnix(payload.ExpiresAt),
		NotBefore: timeFromUnix(payload.NotBefore),
		Metadata:  cloneMetadata(payload.Metadata),
	}
}

func encodeSegment(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeSegment(segment string, dest any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeFromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

func cloneStrings(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

func cloneMetadata(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func randomID() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
