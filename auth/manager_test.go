package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/adeilh/go-rakh/cache"
)

// mockCacheStore implements cache.Store for testing
type mockCacheStore struct {
	mu   sync.RWMutex
	data map[string]cacheEntry
	err  error
}

type cacheEntry struct {
	value []byte
	exp   time.Time
}

func newMockCacheStore() *mockCacheStore {
	return &mockCacheStore{
		data: make(map[string]cacheEntry),
	}
}

func (s *mockCacheStore) Get(ctx context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.err != nil {
		return nil, s.err
	}

	entry, ok := s.data[key]
	if !ok {
		return nil, cache.ErrNotFound
	}

	if !entry.exp.IsZero() && time.Now().After(entry.exp) {
		return nil, cache.ErrNotFound
	}

	return entry.value, nil
}

func (s *mockCacheStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return s.err
	}

	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	s.data[key] = cacheEntry{value: value, exp: exp}
	return nil
}

func (s *mockCacheStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return s.err
	}

	delete(s.data, key)
	return nil
}

func (s *mockCacheStore) setError(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func TestNewManager(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cache := newMockCacheStore()
		mgr, err := NewManager(ManagerConfig{
			Cache:     cache,
			JWTSecret: []byte("test-secret-key-32-bytes-long!!!"),
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		if mgr == nil {
			t.Fatal("NewManager() returned nil")
		}
	})

	t.Run("missing cache", func(t *testing.T) {
		_, err := NewManager(ManagerConfig{
			JWTSecret: []byte("test-secret"),
		})
		if err == nil {
			t.Error("NewManager() should return error when cache is nil")
		}
	})

	t.Run("missing secret", func(t *testing.T) {
		cache := newMockCacheStore()
		_, err := NewManager(ManagerConfig{
			Cache: cache,
		})
		if err == nil {
			t.Error("NewManager() should return error when secret is empty")
		}
	})

	t.Run("with user repository", func(t *testing.T) {
		cache := newMockCacheStore()
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))

		mgr, err := NewManager(ManagerConfig{
			Cache:          cache,
			JWTSecret:      []byte("test-secret-key-32-bytes-long!!!"),
			UserRepository: repo,
			PasswordHasher: hasher,
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		if mgr.users == nil {
			t.Error("User service should be configured")
		}
	})

	t.Run("with algorithms", func(t *testing.T) {
		cache := newMockCacheStore()
		_, err := NewManager(ManagerConfig{
			Cache:         cache,
			JWTSecret:     []byte("test-secret-key-32-bytes-long!!!"),
			JWTAlgorithms: []string{"HS256", "HS512"},
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		cache := newMockCacheStore()
		_, err := NewManager(ManagerConfig{
			Cache:         cache,
			JWTSecret:     []byte("test-secret-key-32-bytes-long!!!"),
			JWTAlgorithms: []string{"RS256"}, // Not supported by HMAC provider
		})
		if err == nil {
			t.Error("NewManager() should return error for invalid algorithm")
		}
	})
}

func TestManager_JWT(t *testing.T) {
	ctx := context.Background()
	cache := newMockCacheStore()
	mgr, _ := NewManager(ManagerConfig{
		Cache:     cache,
		JWTSecret: []byte("test-secret-key-32-bytes-long!!!"),
	})

	t.Run("issue and parse token", func(t *testing.T) {
		claims := JWTClaims{Subject: "user-123"}
		opts := JWTOptions{Issuer: "test", TTL: time.Hour}

		token, err := mgr.IssueToken(ctx, claims, opts)
		if err != nil {
			t.Fatalf("IssueToken() error = %v", err)
		}

		parsed, err := mgr.ParseToken(ctx, token.Raw())
		if err != nil {
			t.Fatalf("ParseToken() error = %v", err)
		}

		if parsed.Claims().Subject != "user-123" {
			t.Errorf("Subject = %s, want user-123", parsed.Claims().Subject)
		}
	})

	t.Run("revoke token", func(t *testing.T) {
		claims := JWTClaims{Subject: "user-456"}
		opts := JWTOptions{TTL: time.Hour}

		token, _ := mgr.IssueToken(ctx, claims, opts)

		err := mgr.RevokeToken(ctx, token.Claims().ID)
		if err != nil {
			t.Fatalf("RevokeToken() error = %v", err)
		}

		_, err = mgr.ParseToken(ctx, token.Raw())
		if !errors.Is(err, ErrJWTRevoked) {
			t.Errorf("ParseToken() after revoke error = %v, want ErrJWTRevoked", err)
		}
	})
}

func TestManager_Session(t *testing.T) {
	ctx := context.Background()
	cache := newMockCacheStore()
	mgr, _ := NewManager(ManagerConfig{
		Cache:          cache,
		JWTSecret:      []byte("test-secret-key-32-bytes-long!!!"),
		SessionOptions: SessionStoreOptions{DefaultTTL: time.Hour},
	})

	t.Run("create and get session", func(t *testing.T) {
		desc := SessionDescriptor{
			Subject:   "user-123",
			IP:        "127.0.0.1",
			UserAgent: "test",
		}

		session, err := mgr.CreateSession(ctx, desc)
		if err != nil {
			t.Fatalf("CreateSession() error = %v", err)
		}

		fetched, err := mgr.GetSession(ctx, session.Descriptor().ID)
		if err != nil {
			t.Fatalf("GetSession() error = %v", err)
		}

		if fetched.Descriptor().Subject != "user-123" {
			t.Errorf("Subject = %s, want user-123", fetched.Descriptor().Subject)
		}
	})

	t.Run("delete session", func(t *testing.T) {
		desc := SessionDescriptor{Subject: "user-456"}
		session, _ := mgr.CreateSession(ctx, desc)

		err := mgr.DeleteSession(ctx, session.Descriptor().ID)
		if err != nil {
			t.Fatalf("DeleteSession() error = %v", err)
		}

		_, err = mgr.GetSession(ctx, session.Descriptor().ID)
		if !errors.Is(err, ErrSessionExpired) {
			t.Errorf("GetSession() after delete error = %v, want ErrSessionExpired", err)
		}
	})

	t.Run("touch session", func(t *testing.T) {
		desc := SessionDescriptor{
			Subject:   "user-789",
			ExpiresAt: time.Now().Add(time.Minute),
		}
		session, _ := mgr.CreateSession(ctx, desc)

		newExpiry := time.Now().Add(2 * time.Hour)
		err := mgr.TouchSession(ctx, session.Descriptor().ID, newExpiry)
		if err != nil {
			t.Fatalf("TouchSession() error = %v", err)
		}

		fetched, _ := mgr.GetSession(ctx, session.Descriptor().ID)
		if fetched.Descriptor().ExpiresAt.Before(time.Now().Add(time.Hour)) {
			t.Error("Session expiry should be extended")
		}
	})
}

func TestManager_User(t *testing.T) {
	ctx := context.Background()

	t.Run("without user service", func(t *testing.T) {
		cache := newMockCacheStore()
		mgr, _ := NewManager(ManagerConfig{
			Cache:     cache,
			JWTSecret: []byte("test-secret-key-32-bytes-long!!!"),
		})

		_, err := mgr.CreateUser(ctx, "test@example.com", []byte("password"), nil)
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("CreateUser() error = %v, want ErrUserInvalidInput", err)
		}

		_, err = mgr.UpdateUser(ctx, User{}, nil)
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("UpdateUser() error = %v, want ErrUserInvalidInput", err)
		}

		_, err = mgr.UpdateUserPartial(ctx, "id", UserPatch{}, nil)
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("UpdateUserPartial() error = %v, want ErrUserInvalidInput", err)
		}

		_, err = mgr.DisableUser(ctx, "id")
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("DisableUser() error = %v, want ErrUserInvalidInput", err)
		}

		_, err = mgr.EnableUser(ctx, "id")
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("EnableUser() error = %v, want ErrUserInvalidInput", err)
		}

		_, err = mgr.SendPasswordReset(ctx, "test@example.com")
		if !errors.Is(err, ErrResetSenderAbsent) {
			t.Errorf("SendPasswordReset() error = %v, want ErrResetSenderAbsent", err)
		}
	})

	t.Run("with user service", func(t *testing.T) {
		cache := newMockCacheStore()
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))

		mgr, _ := NewManager(ManagerConfig{
			Cache:          cache,
			JWTSecret:      []byte("test-secret-key-32-bytes-long!!!"),
			UserRepository: repo,
			PasswordHasher: hasher,
		})

		// Create user
		user, err := mgr.CreateUser(ctx, "test@example.com", []byte("password"), map[string]string{"role": "admin"})
		if err != nil {
			t.Fatalf("CreateUser() error = %v", err)
		}
		if user.Email != "test@example.com" {
			t.Errorf("Email = %s, want test@example.com", user.Email)
		}

		// Update user
		user.Name = "Test User"
		updated, err := mgr.UpdateUser(ctx, user, nil)
		if err != nil {
			t.Fatalf("UpdateUser() error = %v", err)
		}
		if updated.Name != "Test User" {
			t.Errorf("Name = %s, want Test User", updated.Name)
		}

		// Partial update
		newTitle := "Manager"
		partial, err := mgr.UpdateUserPartial(ctx, user.ID, UserPatch{Title: &newTitle}, nil)
		if err != nil {
			t.Fatalf("UpdateUserPartial() error = %v", err)
		}
		if partial.Title != "Manager" {
			t.Errorf("Title = %s, want Manager", partial.Title)
		}

		// Disable user
		disabled, err := mgr.DisableUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("DisableUser() error = %v", err)
		}
		if disabled.Enabled {
			t.Error("User should be disabled")
		}

		// Enable user
		enabled, err := mgr.EnableUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("EnableUser() error = %v", err)
		}
		if !enabled.Enabled {
			t.Error("User should be enabled")
		}
	})

	t.Run("password reset with sender", func(t *testing.T) {
		cache := newMockCacheStore()
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		sender := newMockPasswordResetSender()

		mgr, _ := NewManager(ManagerConfig{
			Cache:          cache,
			JWTSecret:      []byte("test-secret-key-32-bytes-long!!!"),
			UserRepository: repo,
			PasswordHasher: hasher,
			ResetSender:    sender,
		})

		_, _ = mgr.CreateUser(ctx, "test@example.com", []byte("password"), nil)

		token, err := mgr.SendPasswordReset(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("SendPasswordReset() error = %v", err)
		}
		if token == "" {
			t.Error("Token should not be empty")
		}
	})
}

func TestManager_Integration(t *testing.T) {
	ctx := context.Background()
	cache := newMockCacheStore()
	repo := newMockUserRepository()
	hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))

	mgr, err := NewManager(ManagerConfig{
		Cache:          cache,
		JWTSecret:      []byte("test-secret-key-32-bytes-long!!!"),
		SessionOptions: SessionStoreOptions{DefaultTTL: time.Hour},
		UserRepository: repo,
		PasswordHasher: hasher,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// Create user
	user, err := mgr.CreateUser(ctx, "alice@example.com", []byte("SecurePass123"), nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	// Issue JWT for user
	token, err := mgr.IssueToken(ctx, JWTClaims{
		Subject:  user.ID,
		Metadata: map[string]any{"email": user.Email},
	}, JWTOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("IssueToken() error = %v", err)
	}

	// Create session for user
	session, err := mgr.CreateSession(ctx, SessionDescriptor{
		Subject:   user.ID,
		IP:        "192.168.1.1",
		UserAgent: "Mozilla/5.0",
		Metadata:  map[string]string{"jwt_id": token.Claims().ID},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Parse and validate token
	parsed, err := mgr.ParseToken(ctx, token.Raw())
	if err != nil {
		t.Fatalf("ParseToken() error = %v", err)
	}
	if parsed.Claims().Subject != user.ID {
		t.Errorf("Token subject mismatch")
	}

	// Get session
	sess, err := mgr.GetSession(ctx, session.Descriptor().ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if sess.Descriptor().Subject != user.ID {
		t.Errorf("Session subject mismatch")
	}

	// Disable user (simulate logout)
	_, _ = mgr.DisableUser(ctx, user.ID)

	// Revoke token
	_ = mgr.RevokeToken(ctx, token.Claims().ID)

	// Delete session
	_ = mgr.DeleteSession(ctx, session.Descriptor().ID)

	// Verify token is revoked
	_, err = mgr.ParseToken(ctx, token.Raw())
	if !errors.Is(err, ErrJWTRevoked) {
		t.Errorf("Token should be revoked")
	}

	// Verify session is deleted
	_, err = mgr.GetSession(ctx, session.Descriptor().ID)
	if !errors.Is(err, ErrSessionExpired) {
		t.Errorf("Session should be deleted")
	}
}
