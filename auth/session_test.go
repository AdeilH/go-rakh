package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adeilh/go-rakh/cache/redis"
	testredis "github.com/adeilh/go-rakh/internal/testutil/rediscontainer"
)

func TestRedisSessionStoreCreateGetDelete(t *testing.T) {
	store := newRedisSessionStore()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	desc := SessionDescriptor{
		Subject:   "user-123",
		IP:        "127.0.0.1",
		UserAgent: "test-suite",
		Metadata: map[string]string{
			"scope": "admin",
		},
	}

	token, err := store.Create(ctx, desc)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	fetched, err := store.Get(ctx, token.Descriptor().ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if fetched.Descriptor().Subject != desc.Subject {
		t.Fatalf("subject mismatch: got %s want %s", fetched.Descriptor().Subject, desc.Subject)
	}

	if err := store.Delete(ctx, token.Descriptor().ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if _, err := store.Get(ctx, token.Descriptor().ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestRedisSessionStoreTTL(t *testing.T) {
	store := newRedisSessionStore()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	token, err := store.Create(ctx, SessionDescriptor{Subject: "ttl-user", ExpiresAt: time.Now().Add(150 * time.Millisecond)})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	if _, err := store.Get(ctx, token.Descriptor().ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired after TTL, got %v", err)
	}
}

func TestRedisSessionStoreTouch(t *testing.T) {
	store := newRedisSessionStore()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	token, err := store.Create(ctx, SessionDescriptor{Subject: "touch-user", ExpiresAt: time.Now().Add(200 * time.Millisecond)})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	newExpiry := time.Now().Add(600 * time.Millisecond)
	if err := store.Touch(ctx, token.Descriptor().ID, newExpiry); err != nil {
		t.Fatalf("Touch() error = %v", err)
	}

	time.Sleep(400 * time.Millisecond)

	if _, err := store.Get(ctx, token.Descriptor().ID); err != nil {
		t.Fatalf("expected session to persist after touch, got %v", err)
	}
}

func newRedisSessionStore() *CacheSessionStore {
	opts := RedisSessionStoreOptions{
		Prefix:     "session-test",
		DefaultTTL: time.Minute,
		Redis:      redis.Options{Addr: testredis.Addr()},
	}
	return NewRedisSessionStore(opts)
}
