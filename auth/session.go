package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/adeilh/go-rakh/cache"
	"github.com/adeilh/go-rakh/cache/redis"
)

var (
	ErrSessionInvalidDescriptor = errors.New("auth: invalid session descriptor")
	ErrSessionExpired           = errors.New("auth: session expired")
)

type SessionStoreOptions struct {
	Prefix     string
	DefaultTTL time.Duration
}

type CacheSessionStore struct {
	store      cache.Store
	prefix     string
	defaultTTL time.Duration
	now        func() time.Time
}

func NewCacheSessionStore(store cache.Store, opts SessionStoreOptions) *CacheSessionStore {
	prefix := opts.Prefix
	if prefix == "" {
		prefix = "session"
	}
	ttl := opts.DefaultTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &CacheSessionStore{
		store:      store,
		prefix:     prefix,
		defaultTTL: ttl,
		now:        time.Now,
	}
}

type RedisSessionStoreOptions struct {
	Prefix     string
	DefaultTTL time.Duration
	Redis      redis.Options
}

func NewRedisSessionStore(opts RedisSessionStoreOptions) *CacheSessionStore {
	return NewCacheSessionStore(
		redis.NewStore(opts.Redis),
		SessionStoreOptions{Prefix: opts.Prefix, DefaultTTL: opts.DefaultTTL},
	)
}

func (s *CacheSessionStore) key(id string) string {
	return fmt.Sprintf("%s:%s", s.prefix, id)
}

func (s *CacheSessionStore) Create(ctx context.Context, desc SessionDescriptor) (SessionToken, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	prepared, ttl, err := s.prepareDescriptor(desc)
	if err != nil {
		return nil, err
	}
	record, err := json.Marshal(prepared)
	if err != nil {
		return nil, err
	}
	if err := s.store.Set(ctx, s.key(prepared.ID), record, ttl); err != nil {
		return nil, err
	}
	return sessionToken{desc: prepared}, nil
}

// Get fetches a session token by ID.
func (s *CacheSessionStore) Get(ctx context.Context, id string) (SessionToken, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if id == "" {
		return nil, ErrSessionInvalidDescriptor
	}

	payload, err := s.store.Get(ctx, s.key(id))
	if err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			return nil, ErrSessionExpired
		}
		return nil, err
	}

	var desc SessionDescriptor
	if err := json.Unmarshal(payload, &desc); err != nil {
		return nil, err
	}

	if desc.ExpiresAt.Before(s.now()) {
		_ = s.store.Delete(ctx, s.key(id))
		return nil, ErrSessionExpired
	}

	return sessionToken{desc: desc}, nil
}

// Delete removes a session by ID.
func (s *CacheSessionStore) Delete(ctx context.Context, id string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if id == "" {
		return ErrSessionInvalidDescriptor
	}

	if err := s.store.Delete(ctx, s.key(id)); err != nil && !errors.Is(err, cache.ErrNotFound) {
		return err
	}
	return nil
}

// Touch extends the expiry of a session.
func (s *CacheSessionStore) Touch(ctx context.Context, id string, expiresAt time.Time) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if id == "" {
		return ErrSessionInvalidDescriptor
	}
	if expiresAt.Before(s.now()) {
		return ErrSessionExpired
	}

	token, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	desc := token.Descriptor()
	desc.ExpiresAt = expiresAt
	payload, err := json.Marshal(desc)
	if err != nil {
		return err
	}

	ttl := expiresAt.Sub(s.now())
	if ttl <= 0 {
		return ErrSessionExpired
	}

	return s.store.Set(ctx, s.key(id), payload, ttl)
}

func (s *CacheSessionStore) prepareDescriptor(desc SessionDescriptor) (SessionDescriptor, time.Duration, error) {
	if desc.Subject == "" {
		return SessionDescriptor{}, 0, ErrSessionInvalidDescriptor
	}

	out := desc
	out.Metadata = cloneSessionMetadata(desc.Metadata)

	now := s.now()
	if out.ID == "" {
		id, err := randomID()
		if err != nil {
			return SessionDescriptor{}, 0, err
		}
		out.ID = id
	}
	if out.IssuedAt.IsZero() {
		out.IssuedAt = now
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = out.IssuedAt.Add(s.defaultTTL)
	}
	if out.ExpiresAt.Before(out.IssuedAt) {
		return SessionDescriptor{}, 0, ErrSessionInvalidDescriptor
	}

	ttl := out.ExpiresAt.Sub(now)
	if ttl <= 0 {
		ttl = time.Second
	}

	return out, ttl, nil
}

type sessionToken struct {
	desc SessionDescriptor
}

func (t sessionToken) Descriptor() SessionDescriptor { return t.desc }

func (t sessionToken) IsExpired(at time.Time) bool {
	if t.desc.ExpiresAt.IsZero() {
		return false
	}
	return !at.Before(t.desc.ExpiresAt)
}

func cloneSessionMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
