package auth

import (
	"github.com/adeilh/go-rakh/cache"
	"github.com/adeilh/go-rakh/cache/redis"
)

// JWTProviderConfig describes how to bootstrap an HMACJWTProvider backed by
// an arbitrary cache.Store implementation.
type JWTProviderConfig struct {
	Secret     []byte
	Algorithms []string
	Store      cache.Store
}

// NewJWTProvider constructs an HMACJWTProvider that persists tokens via the
// supplied cache store.
func NewJWTProvider(cfg JWTProviderConfig) (*HMACJWTProvider, error) {
	provider, err := NewHMACJWTProvider(cfg.Secret, cfg.Algorithms...)
	if err != nil {
		return nil, err
	}
	provider.UseCache(cfg.Store)
	return provider, nil
}

// NewRedisJWTProvider remains as a convenience helper for Redis users.
type JWTProviderRedisOptions struct {
	Secret     []byte
	Algorithms []string
	Redis      redis.Options
}

func NewRedisJWTProvider(cfg JWTProviderRedisOptions) (*HMACJWTProvider, error) {
	store := redis.NewStore(cfg.Redis)
	return NewJWTProvider(JWTProviderConfig{
		Secret:     cfg.Secret,
		Algorithms: cfg.Algorithms,
		Store:      store,
	})
}
