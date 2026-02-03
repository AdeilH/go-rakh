package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Mock implementations for testing

type mockUserRepository struct {
	mu      sync.RWMutex
	users   map[string]User
	byEmail map[string]string // email -> id
	err     error
}

func newMockUserRepository() *mockUserRepository {
	return &mockUserRepository{
		users:   make(map[string]User),
		byEmail: make(map[string]string),
	}
}

func (r *mockUserRepository) CreateUser(ctx context.Context, user User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.err != nil {
		return r.err
	}

	if _, exists := r.byEmail[user.Email]; exists {
		return ErrUserEmailInUse
	}

	r.users[user.ID] = user
	r.byEmail[user.Email] = user.ID
	return nil
}

func (r *mockUserRepository) UpdateUser(ctx context.Context, user User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.err != nil {
		return r.err
	}

	if _, exists := r.users[user.ID]; !exists {
		return ErrUserNotFound
	}

	r.users[user.ID] = user
	return nil
}

func (r *mockUserRepository) UpdateUserPartial(ctx context.Context, userID string, patch UserPatch) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.err != nil {
		return User{}, r.err
	}

	user, exists := r.users[userID]
	if !exists {
		return User{}, ErrUserNotFound
	}

	if patch.Email != nil {
		user.Email = *patch.Email
	}
	if patch.Name != nil {
		user.Name = *patch.Name
	}
	if patch.Title != nil {
		user.Title = *patch.Title
	}
	if patch.PasswordHash != nil {
		user.PasswordHash = *patch.PasswordHash
	}
	if patch.Enabled != nil {
		user.Enabled = *patch.Enabled
	}
	if patch.Metadata != nil {
		user.Metadata = patch.Metadata
	}

	r.users[userID] = user
	return user, nil
}

func (r *mockUserRepository) DisableUser(ctx context.Context, userID string) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.err != nil {
		return User{}, r.err
	}

	user, exists := r.users[userID]
	if !exists {
		return User{}, ErrUserNotFound
	}

	user.Enabled = false
	r.users[userID] = user
	return user, nil
}

func (r *mockUserRepository) EnableUser(ctx context.Context, userID string) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.err != nil {
		return User{}, r.err
	}

	user, exists := r.users[userID]
	if !exists {
		return User{}, ErrUserNotFound
	}

	user.Enabled = true
	r.users[userID] = user
	return user, nil
}

func (r *mockUserRepository) GetUserByEmail(ctx context.Context, email string) (User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.err != nil {
		return User{}, r.err
	}

	userID, exists := r.byEmail[email]
	if !exists {
		return User{}, ErrUserNotFound
	}

	return r.users[userID], nil
}

func (r *mockUserRepository) setError(err error) {
	r.mu.Lock()
	r.err = err
	r.mu.Unlock()
}

func (r *mockUserRepository) getUser(id string) (User, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	user, ok := r.users[id]
	return user, ok
}

type mockPasswordResetSender struct {
	mu   sync.Mutex
	sent []struct {
		user  User
		token string
	}
	err error
}

func newMockPasswordResetSender() *mockPasswordResetSender {
	return &mockPasswordResetSender{}
}

func (s *mockPasswordResetSender) SendResetToken(ctx context.Context, user User, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return s.err
	}

	s.sent = append(s.sent, struct {
		user  User
		token string
	}{user, token})
	return nil
}

func (s *mockPasswordResetSender) setError(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *mockPasswordResetSender) getSent() []struct {
	user  User
	token string
} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]struct {
		user  User
		token string
	}{}, s.sent...)
}

// Tests

func TestNewUserService(t *testing.T) {
	repo := newMockUserRepository()
	hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))

	t.Run("valid config", func(t *testing.T) {
		svc, err := NewUserService(UserServiceConfig{
			Repository: repo,
			Hasher:     hasher,
		})
		if err != nil {
			t.Fatalf("NewUserService() error = %v", err)
		}
		if svc == nil {
			t.Fatal("NewUserService() returned nil")
		}
	})

	t.Run("missing repository", func(t *testing.T) {
		_, err := NewUserService(UserServiceConfig{
			Hasher: hasher,
		})
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("NewUserService() error = %v, want ErrUserInvalidInput", err)
		}
	})

	t.Run("missing hasher", func(t *testing.T) {
		_, err := NewUserService(UserServiceConfig{
			Repository: repo,
		})
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("NewUserService() error = %v, want ErrUserInvalidInput", err)
		}
	})

	t.Run("with optional dependencies", func(t *testing.T) {
		sender := newMockPasswordResetSender()
		now := time.Now()

		svc, err := NewUserService(UserServiceConfig{
			Repository:   repo,
			Hasher:       hasher,
			ResetSender:  sender,
			TokenFactory: func() (string, error) { return "test-token", nil },
			Now:          func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("NewUserService() error = %v", err)
		}
		if svc == nil {
			t.Fatal("NewUserService() returned nil")
		}
	})
}

func TestUserService_CreateUser(t *testing.T) {
	ctx := context.Background()

	t.Run("successful creation", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		user, err := svc.CreateUser(ctx, "test@example.com", []byte("password"), map[string]string{"role": "admin"})
		if err != nil {
			t.Fatalf("CreateUser() error = %v", err)
		}

		if user.ID == "" {
			t.Error("User ID is empty")
		}
		if user.Email != "test@example.com" {
			t.Errorf("Email = %s, want test@example.com", user.Email)
		}
		if !user.Enabled {
			t.Error("User should be enabled by default")
		}
		if user.PasswordHash.Algorithm != AlgorithmBcrypt {
			t.Errorf("PasswordHash.Algorithm = %s, want bcrypt", user.PasswordHash.Algorithm)
		}
		if user.Metadata["role"] != "admin" {
			t.Error("Metadata not preserved")
		}
	})

	t.Run("empty email", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		_, err := svc.CreateUser(ctx, "", []byte("password"), nil)
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("CreateUser() error = %v, want ErrUserInvalidInput", err)
		}
	})

	t.Run("empty password", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		_, err := svc.CreateUser(ctx, "test@example.com", nil, nil)
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("CreateUser() error = %v, want ErrUserInvalidInput", err)
		}
	})

	t.Run("duplicate email", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		_, _ = svc.CreateUser(ctx, "test@example.com", []byte("password"), nil)
		_, err := svc.CreateUser(ctx, "test@example.com", []byte("password2"), nil)
		if !errors.Is(err, ErrUserEmailInUse) {
			t.Errorf("CreateUser() error = %v, want ErrUserEmailInUse", err)
		}
	})

	t.Run("repository error", func(t *testing.T) {
		repo := newMockUserRepository()
		repo.setError(errors.New("db error"))
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		_, err := svc.CreateUser(ctx, "test@example.com", []byte("password"), nil)
		if err == nil {
			t.Error("CreateUser() should return error")
		}
	})
}

func TestUserService_UpdateUser(t *testing.T) {
	ctx := context.Background()

	t.Run("update without password change", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		user, _ := svc.CreateUser(ctx, "test@example.com", []byte("password"), nil)
		user.Name = "Updated Name"

		updated, err := svc.UpdateUser(ctx, user, nil)
		if err != nil {
			t.Fatalf("UpdateUser() error = %v", err)
		}

		if updated.Name != "Updated Name" {
			t.Errorf("Name = %s, want Updated Name", updated.Name)
		}
	})

	t.Run("update with password change", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		user, _ := svc.CreateUser(ctx, "test@example.com", []byte("oldpass"), nil)
		oldHash := user.PasswordHash

		updated, err := svc.UpdateUser(ctx, user, []byte("newpass"))
		if err != nil {
			t.Fatalf("UpdateUser() error = %v", err)
		}

		if string(updated.PasswordHash.Value) == string(oldHash.Value) {
			t.Error("Password hash should have changed")
		}
	})

	t.Run("empty email", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		_, err := svc.UpdateUser(ctx, User{}, nil)
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("UpdateUser() error = %v, want ErrUserInvalidInput", err)
		}
	})
}

func TestUserService_UpdateUserPartial(t *testing.T) {
	ctx := context.Background()

	t.Run("partial update", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		user, _ := svc.CreateUser(ctx, "test@example.com", []byte("password"), nil)

		newName := "New Name"
		updated, err := svc.UpdateUserPartial(ctx, user.ID, UserPatch{Name: &newName}, nil)
		if err != nil {
			t.Fatalf("UpdateUserPartial() error = %v", err)
		}

		if updated.Name != "New Name" {
			t.Errorf("Name = %s, want New Name", updated.Name)
		}
	})

	t.Run("partial update with password", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		user, _ := svc.CreateUser(ctx, "test@example.com", []byte("oldpass"), nil)

		updated, err := svc.UpdateUserPartial(ctx, user.ID, UserPatch{}, []byte("newpass"))
		if err != nil {
			t.Fatalf("UpdateUserPartial() error = %v", err)
		}

		// Verify new password works
		if err := hasher.Compare(ctx, []byte("newpass"), updated.PasswordHash); err != nil {
			t.Error("New password should work")
		}
	})

	t.Run("empty user ID", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

		_, err := svc.UpdateUserPartial(ctx, "", UserPatch{}, nil)
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("UpdateUserPartial() error = %v, want ErrUserInvalidInput", err)
		}
	})
}

func TestUserService_DisableEnableUser(t *testing.T) {
	ctx := context.Background()
	repo := newMockUserRepository()
	hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
	svc, _ := NewUserService(UserServiceConfig{Repository: repo, Hasher: hasher})

	user, _ := svc.CreateUser(ctx, "test@example.com", []byte("password"), nil)

	t.Run("disable user", func(t *testing.T) {
		disabled, err := svc.DisableUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("DisableUser() error = %v", err)
		}
		if disabled.Enabled {
			t.Error("User should be disabled")
		}
	})

	t.Run("enable user", func(t *testing.T) {
		enabled, err := svc.EnableUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("EnableUser() error = %v", err)
		}
		if !enabled.Enabled {
			t.Error("User should be enabled")
		}
	})

	t.Run("disable empty ID", func(t *testing.T) {
		_, err := svc.DisableUser(ctx, "")
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("DisableUser() error = %v, want ErrUserInvalidInput", err)
		}
	})

	t.Run("enable empty ID", func(t *testing.T) {
		_, err := svc.EnableUser(ctx, "")
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("EnableUser() error = %v, want ErrUserInvalidInput", err)
		}
	})

	t.Run("disable non-existent user", func(t *testing.T) {
		_, err := svc.DisableUser(ctx, "non-existent-id")
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("DisableUser() error = %v, want ErrUserNotFound", err)
		}
	})
}

func TestUserService_SendPasswordReset(t *testing.T) {
	ctx := context.Background()

	t.Run("successful reset", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		sender := newMockPasswordResetSender()
		svc, _ := NewUserService(UserServiceConfig{
			Repository:  repo,
			Hasher:      hasher,
			ResetSender: sender,
		})

		_, _ = svc.CreateUser(ctx, "test@example.com", []byte("password"), nil)

		token, err := svc.SendPasswordReset(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("SendPasswordReset() error = %v", err)
		}
		if token == "" {
			t.Error("Token should not be empty")
		}

		sent := sender.getSent()
		if len(sent) != 1 {
			t.Errorf("Expected 1 sent reset, got %d", len(sent))
		}
	})

	t.Run("no sender configured", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		svc, _ := NewUserService(UserServiceConfig{
			Repository: repo,
			Hasher:     hasher,
		})

		_, _ = svc.CreateUser(ctx, "test@example.com", []byte("password"), nil)

		_, err := svc.SendPasswordReset(ctx, "test@example.com")
		if !errors.Is(err, ErrResetSenderAbsent) {
			t.Errorf("SendPasswordReset() error = %v, want ErrResetSenderAbsent", err)
		}
	})

	t.Run("empty email", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		sender := newMockPasswordResetSender()
		svc, _ := NewUserService(UserServiceConfig{
			Repository:  repo,
			Hasher:      hasher,
			ResetSender: sender,
		})

		_, err := svc.SendPasswordReset(ctx, "")
		if !errors.Is(err, ErrUserInvalidInput) {
			t.Errorf("SendPasswordReset() error = %v, want ErrUserInvalidInput", err)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		sender := newMockPasswordResetSender()
		svc, _ := NewUserService(UserServiceConfig{
			Repository:  repo,
			Hasher:      hasher,
			ResetSender: sender,
		})

		_, err := svc.SendPasswordReset(ctx, "nonexistent@example.com")
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("SendPasswordReset() error = %v, want ErrUserNotFound", err)
		}
	})

	t.Run("sender error", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		sender := newMockPasswordResetSender()
		sender.setError(errors.New("send error"))
		svc, _ := NewUserService(UserServiceConfig{
			Repository:  repo,
			Hasher:      hasher,
			ResetSender: sender,
		})

		_, _ = svc.CreateUser(ctx, "test@example.com", []byte("password"), nil)

		_, err := svc.SendPasswordReset(ctx, "test@example.com")
		if err == nil {
			t.Error("SendPasswordReset() should return error")
		}
	})

	t.Run("custom token factory", func(t *testing.T) {
		repo := newMockUserRepository()
		hasher := NewBcryptHasher(WithBcryptCost(4), WithBcryptValidation(PasswordValidationOptions{MinLength: 1}))
		sender := newMockPasswordResetSender()
		svc, _ := NewUserService(UserServiceConfig{
			Repository:   repo,
			Hasher:       hasher,
			ResetSender:  sender,
			TokenFactory: func() (string, error) { return "custom-token", nil },
		})

		_, _ = svc.CreateUser(ctx, "test@example.com", []byte("password"), nil)

		token, err := svc.SendPasswordReset(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("SendPasswordReset() error = %v", err)
		}
		if token != "custom-token" {
			t.Errorf("Token = %s, want custom-token", token)
		}
	})
}

func TestCloneUserMetadata(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := cloneUserMetadata(nil)
		if result != nil {
			t.Error("Expected nil for nil input")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		result := cloneUserMetadata(map[string]string{})
		if result != nil {
			t.Error("Expected nil for empty input")
		}
	})

	t.Run("with data", func(t *testing.T) {
		input := map[string]string{"key": "value"}
		result := cloneUserMetadata(input)

		if result["key"] != "value" {
			t.Error("Clone should preserve data")
		}

		// Modify original
		input["key"] = "modified"
		if result["key"] == "modified" {
			t.Error("Clone should be independent of original")
		}
	})
}

func TestRandomToken(t *testing.T) {
	t.Run("generates non-empty token", func(t *testing.T) {
		token, err := randomToken()
		if err != nil {
			t.Fatalf("randomToken() error = %v", err)
		}
		if token == "" {
			t.Error("Token should not be empty")
		}
	})

	t.Run("generates unique tokens", func(t *testing.T) {
		seen := make(map[string]struct{})
		for i := 0; i < 100; i++ {
			token, _ := randomToken()
			if _, exists := seen[token]; exists {
				t.Error("Duplicate token generated")
			}
			seen[token] = struct{}{}
		}
	})
}
