package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrUserNotFound      = errors.New("auth: user not found")
	ErrUserEmailInUse    = errors.New("auth: email already in use")
	ErrUserInvalidInput  = errors.New("auth: invalid user input")
	ErrResetSenderAbsent = errors.New("auth: password reset sender missing")
)

// User models the data persisted inside the user's chosen datastore.
type User struct {
	ID           string
	Email        string
	Name         string
	Title        string
	PasswordHash PasswordHash
	Metadata     map[string]string
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserRepository abstracts persistence so callers can map to any table schema.
type UserRepository interface {
	CreateUser(ctx context.Context, user User) error
	UpdateUser(ctx context.Context, user User) error
	UpdateUserPartial(ctx context.Context, userID string, patch UserPatch) (User, error)
	DisableUser(ctx context.Context, userID string) (User, error)
	EnableUser(ctx context.Context, userID string) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
}

// PasswordResetSender delivers reset tokens out-of-band (email, SMS, etc.).
type PasswordResetSender interface {
	SendResetToken(ctx context.Context, user User, token string) error
}

// UserService orchestrates hashing, repository persistence, and reset tokens.
type UserService struct {
	repo         UserRepository
	hasher       PasswordHasher
	resetSender  PasswordResetSender
	now          func() time.Time
	tokenFactory func() (string, error)
}

// UserServiceConfig wires dependencies for UserService.
type UserServiceConfig struct {
	Repository   UserRepository
	Hasher       PasswordHasher
	ResetSender  PasswordResetSender
	TokenFactory func() (string, error)
	Now          func() time.Time
}

func NewUserService(cfg UserServiceConfig) (*UserService, error) {
	if cfg.Repository == nil || cfg.Hasher == nil {
		return nil, ErrUserInvalidInput
	}
	svc := &UserService{
		repo:         cfg.Repository,
		hasher:       cfg.Hasher,
		resetSender:  cfg.ResetSender,
		now:          cfg.Now,
		tokenFactory: cfg.TokenFactory,
	}
	if svc.now == nil {
		svc.now = time.Now
	}
	if svc.tokenFactory == nil {
		svc.tokenFactory = randomToken
	}
	return svc, nil
}

// CreateUser hashes the provided plaintext password and persists the record.
func (s *UserService) CreateUser(ctx context.Context, email string, plainPassword []byte, metadata map[string]string) (User, error) {
	if email == "" || len(plainPassword) == 0 {
		return User{}, ErrUserInvalidInput
	}
	hash, err := s.hasher.Hash(ctx, plainPassword, PasswordOptions{})
	if err != nil {
		return User{}, err
	}
	id, err := randomID()
	if err != nil {
		return User{}, err
	}
	now := s.now()
	user := User{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		Metadata:     cloneUserMetadata(metadata),
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.repo.CreateUser(ctx, user); err != nil {
		return User{}, err
	}
	return user, nil
}

// UpdateUser changes metadata or password; plaintext is optional.
func (s *UserService) UpdateUser(ctx context.Context, user User, newPlainPassword []byte) (User, error) {
	if user.Email == "" {
		return User{}, ErrUserInvalidInput
	}
	if len(newPlainPassword) > 0 {
		hash, err := s.hasher.Hash(ctx, newPlainPassword, PasswordOptions{})
		if err != nil {
			return User{}, err
		}
		user.PasswordHash = hash
	}
	user.Metadata = cloneUserMetadata(user.Metadata)
	user.UpdatedAt = s.now()
	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return User{}, err
	}
	return user, nil
}

// UpdateUserPartial merges changes onto the existing user using the repository patch method.
func (s *UserService) UpdateUserPartial(ctx context.Context, userID string, patch UserPatch, newPlainPassword []byte) (User, error) {
	if userID == "" {
		return User{}, ErrUserInvalidInput
	}
	if len(newPlainPassword) > 0 {
		hash, err := s.hasher.Hash(ctx, newPlainPassword, PasswordOptions{})
		if err != nil {
			return User{}, err
		}
		patch.PasswordHash = &hash
	}
	if patch.Enabled != nil {
		// pass through; repository decides merge
	}
	return s.repo.UpdateUserPartial(ctx, userID, patch)
}

// SendPasswordReset locates the user, generates a token, and dispatches it.
func (s *UserService) SendPasswordReset(ctx context.Context, email string) (string, error) {
	if email == "" {
		return "", ErrUserInvalidInput
	}
	if s.resetSender == nil {
		return "", ErrResetSenderAbsent
	}
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return "", err
	}
	token, err := s.tokenFactory()
	if err != nil {
		return "", err
	}
	if err := s.resetSender.SendResetToken(ctx, user, token); err != nil {
		return "", err
	}
	return token, nil
}

// DisableUser marks a user as disabled instead of deleting.
func (s *UserService) DisableUser(ctx context.Context, userID string) (User, error) {
	if userID == "" {
		return User{}, ErrUserInvalidInput
	}
	return s.repo.DisableUser(ctx, userID)
}

// EnableUser re-enables a previously disabled user.
func (s *UserService) EnableUser(ctx context.Context, userID string) (User, error) {
	if userID == "" {
		return User{}, ErrUserInvalidInput
	}
	return s.repo.EnableUser(ctx, userID)
}

// UserPatch allows partial updates without requiring all fields.
type UserPatch struct {
	Email        *string
	Name         *string
	Title        *string
	PasswordHash *PasswordHash
	Metadata     map[string]string
	Enabled      *bool
}

// Default schema snippet developers can adapt when creating their own tables.
const DefaultUserTableSchema = `CREATE TABLE users (
    id UUID PRIMARY KEY,
    email CITEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    title TEXT NOT NULL,
    password_hash JSONB NOT NULL,
    metadata JSONB,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);`

func randomToken() (string, error) {
	token, err := randomID()
	if err != nil {
		return "", fmt.Errorf("generate reset token: %w", err)
	}
	return token, nil
}

func cloneUserMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
