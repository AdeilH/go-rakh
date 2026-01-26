package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/adeilh/go-rakh/cache"
	"github.com/adeilh/go-rakh/cache/redis"
	testredis "github.com/adeilh/go-rakh/internal/testutil/rediscontainer"
)

func TestMain(m *testing.M) {
	if err := testredis.Setup(); err != nil {
		fmt.Println("auth jwt tests skipped:", err)
		os.Exit(0)
	}

	code := m.Run()

	if err := testredis.Teardown(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to stop redis test container:", err)
	}

	os.Exit(code)
}

func TestHMACJWTProviderIssueParse(t *testing.T) {
	provider := newRedisProvider(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	claims := JWTClaims{Subject: "user-1"}
	opts := JWTOptions{Issuer: "go-rakh", TTL: time.Minute}

	token, err := provider.Issue(ctx, claims, opts)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	parsed, err := provider.Parse(ctx, token.Raw())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if parsed.Claims().Subject != claims.Subject {
		t.Fatalf("Parse() subject = %s, want %s", parsed.Claims().Subject, claims.Subject)
	}
}

func TestHMACJWTProviderRevocation(t *testing.T) {
	provider := newRedisProvider(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	token, err := provider.Issue(ctx, JWTClaims{Subject: "user"}, JWTOptions{Issuer: "go-rakh", TTL: time.Minute})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if err := provider.Revoke(ctx, token.Claims().ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	if _, err := provider.Parse(ctx, token.Raw()); !errors.Is(err, ErrJWTRevoked) {
		t.Fatalf("Parse() error = %v, want ErrJWTRevoked", err)
	}
}

func TestHMACJWTProviderCacheConsistency(t *testing.T) {
	store := redis.NewStore(redis.Options{Addr: testredis.Addr()})
	provider := newProviderWithStore(t, store)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	token, err := provider.Issue(ctx, JWTClaims{Subject: "cache"}, JWTOptions{Issuer: "go-rakh", TTL: time.Minute})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if err := store.Delete(ctx, provider.cacheKey(token.Claims().ID)); err != nil {
		t.Fatalf("failed to delete token from redis: %v", err)
	}

	if _, err := provider.Parse(ctx, token.Raw()); !errors.Is(err, ErrJWTRevoked) {
		t.Fatalf("Parse() error = %v, want ErrJWTRevoked after cache delete", err)
	}
}

func TestHMACJWTProviderTTLExpiry(t *testing.T) {
	store := redis.NewStore(redis.Options{Addr: testredis.Addr()})
	provider := newProviderWithStore(t, store)
	provider.SetLeeway(0)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	token, err := provider.Issue(ctx, JWTClaims{Subject: "ttl"}, JWTOptions{Issuer: "go-rakh", TTL: 250 * time.Millisecond})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	time.Sleep(400 * time.Millisecond)

	if _, err := provider.Parse(ctx, token.Raw()); !errors.Is(err, ErrJWTExpired) && !errors.Is(err, ErrJWTRevoked) {
		t.Fatalf("expected ErrJWTExpired or ErrJWTRevoked, got %v", err)
	}

	if _, err := store.Get(ctx, provider.cacheKey(token.Claims().ID)); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("expected cache.ErrNotFound after TTL, got %v", err)
	}
}

func TestJWTIntegrationRoundTrip(t *testing.T) {
	store := redis.NewStore(redis.Options{Addr: testredis.Addr()})
	provider, err := NewHMACJWTProvider([]byte("integration-secret"), "HS512")
	if err != nil {
		t.Fatalf("NewHMACJWTProvider() error = %v", err)
	}
	provider.UseCache(store)
	provider.SetCachePrefix("jwt-integration")
	provider.SetLeeway(2 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	issuedAt := time.Unix(time.Now().Unix(), 0).UTC()
	claims := JWTClaims{
		Subject:  "integration-user",
		IssuedAt: issuedAt,
		Metadata: map[string]any{
			"role": "admin",
			"tier": "gold",
		},
	}
	opts := JWTOptions{
		Issuer:    "integration-suite",
		Audience:  []string{"core-service", "mobile-app"},
		TTL:       90 * time.Second,
		ClockSkew: 15 * time.Second,
		KeyID:     "kid-int-1",
		Algorithm: "HS512",
	}

	token, err := provider.Issue(ctx, claims, opts)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	cacheKey := provider.cacheKey(token.Claims().ID)
	rawFromStore, err := store.Get(ctx, cacheKey)
	if err != nil {
		t.Fatalf("Get() from redis error = %v", err)
	}
	if token.Raw() != string(rawFromStore) {
		t.Fatalf("stored token mismatch: redis=%q token=%q", rawFromStore, token.Raw())
	}

	parsed, err := provider.Parse(ctx, string(rawFromStore))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	parsedClaims := parsed.Claims()
	if parsedClaims.ID == "" {
		t.Fatal("expected non-empty token ID")
	}
	if parsedClaims.Subject != claims.Subject {
		t.Fatalf("subject mismatch: got %s want %s", parsedClaims.Subject, claims.Subject)
	}
	if parsedClaims.Issuer != opts.Issuer {
		t.Fatalf("issuer mismatch: got %s want %s", parsedClaims.Issuer, opts.Issuer)
	}
	if !equalStrings(parsedClaims.Audience, opts.Audience) {
		t.Fatalf("audience mismatch: got %v want %v", parsedClaims.Audience, opts.Audience)
	}
	if !parsedClaims.IssuedAt.Equal(issuedAt) {
		t.Fatalf("issuedAt mismatch: got %s want %s", parsedClaims.IssuedAt, issuedAt)
	}
	expiresDelta := parsedClaims.ExpiresAt.Sub(parsedClaims.IssuedAt)
	if expiresDelta != opts.TTL {
		t.Fatalf("ttl mismatch: got %s want %s", expiresDelta, opts.TTL)
	}
	expectedNotBefore := issuedAt.Add(-opts.ClockSkew)
	if !parsedClaims.NotBefore.Equal(expectedNotBefore) {
		t.Fatalf("notBefore mismatch: got %s want %s", parsedClaims.NotBefore, expectedNotBefore)
	}
	if parsedClaims.Metadata["role"] != "admin" || parsedClaims.Metadata["tier"] != "gold" {
		t.Fatalf("metadata mismatch: %v", parsedClaims.Metadata)
	}
	if !parsed.IssuedAt().Equal(parsedClaims.IssuedAt) || !parsed.ExpiresAt().Equal(parsedClaims.ExpiresAt) {
		t.Fatalf("token accessors mismatch: issuedAt=%s expiresAt=%s", parsed.IssuedAt(), parsed.ExpiresAt())
	}

	if err := provider.Revoke(ctx, parsedClaims.ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
}

func newRedisProvider(t *testing.T) *HMACJWTProvider {
	store := redis.NewStore(redis.Options{Addr: testredis.Addr()})
	return newProviderWithStore(t, store)
}

func newProviderWithStore(t *testing.T, store *redis.Store) *HMACJWTProvider {
	t.Helper()
	provider, err := NewHMACJWTProvider([]byte("super-secret"))
	if err != nil {
		t.Fatalf("NewHMACJWTProvider() error = %v", err)
	}
	provider.UseCache(store)
	provider.SetCachePrefix("jwt-test")
	return provider
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
