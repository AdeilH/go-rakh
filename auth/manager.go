package auth

import (
	"context"
	"time"

	"github.com/adeilh/go-rakh/cache"
)

// Manager bundles JWT, session, and user workflows behind a single façade.
type Manager struct {
	tokens   JWTTokenProvider
	sessions SessionStore
	users    *UserService
}

// ManagerConfig wires the dependencies required for Manager.
type ManagerConfig struct {
	Cache           cache.Store
	JWTSecret       []byte
	JWTAlgorithms   []string
	JWTOptions      JWTOptions
	SessionOptions  SessionStoreOptions
	UserRepository  UserRepository
	PasswordHasher  PasswordHasher
	ResetSender     PasswordResetSender
	ResetTokenMaker func() (string, error)
	Now             func() time.Time
}

// NewManager builds a Manager with the provided dependencies.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Cache == nil {
		return nil, ErrJWTInvalidClaims
	}
	tokenProvider, err := NewJWTProvider(JWTProviderConfig{
		Secret:     cfg.JWTSecret,
		Algorithms: cfg.JWTAlgorithms,
		Store:      cfg.Cache,
	})
	if err != nil {
		return nil, err
	}

	sessionStore := NewCacheSessionStore(cfg.Cache, cfg.SessionOptions)

	var userService *UserService
	if cfg.UserRepository != nil && cfg.PasswordHasher != nil {
		userService, err = NewUserService(UserServiceConfig{
			Repository:   cfg.UserRepository,
			Hasher:       cfg.PasswordHasher,
			ResetSender:  cfg.ResetSender,
			TokenFactory: cfg.ResetTokenMaker,
			Now:          cfg.Now,
		})
		if err != nil {
			return nil, err
		}
	}

	return &Manager{
		tokens:   tokenProvider,
		sessions: sessionStore,
		users:    userService,
	}, nil
}

// IssueToken wraps JWT issuance via the configured provider.
func (m *Manager) IssueToken(ctx context.Context, claims JWTClaims, opts JWTOptions) (JWTToken, error) {
	return m.tokens.Issue(ctx, claims, opts)
}

// ParseToken validates and returns the JWT token instance.
func (m *Manager) ParseToken(ctx context.Context, raw string) (JWTToken, error) {
	return m.tokens.Parse(ctx, raw)
}

// RevokeToken revokes the provided token ID.
func (m *Manager) RevokeToken(ctx context.Context, tokenID string) error {
	return m.tokens.Revoke(ctx, tokenID)
}

// CreateSession issues a new session entry.
func (m *Manager) CreateSession(ctx context.Context, desc SessionDescriptor) (SessionToken, error) {
	return m.sessions.Create(ctx, desc)
}

// GetSession fetches a session by ID.
func (m *Manager) GetSession(ctx context.Context, id string) (SessionToken, error) {
	return m.sessions.Get(ctx, id)
}

// DeleteSession removes a session from the store.
func (m *Manager) DeleteSession(ctx context.Context, id string) error {
	return m.sessions.Delete(ctx, id)
}

// TouchSession extends a session expiration.
func (m *Manager) TouchSession(ctx context.Context, id string, expiresAt time.Time) error {
	return m.sessions.Touch(ctx, id, expiresAt)
}

// CreateUser proxies to the user service if configured.
func (m *Manager) CreateUser(ctx context.Context, email string, password []byte, metadata map[string]string) (User, error) {
	if m.users == nil {
		return User{}, ErrUserInvalidInput
	}
	return m.users.CreateUser(ctx, email, password, metadata)
}

// UpdateUser proxies user updates.
func (m *Manager) UpdateUser(ctx context.Context, user User, newPassword []byte) (User, error) {
	if m.users == nil {
		return User{}, ErrUserInvalidInput
	}
	return m.users.UpdateUser(ctx, user, newPassword)
}

// UpdateUserPartial proxies partial updates including optional password hash.
func (m *Manager) UpdateUserPartial(ctx context.Context, userID string, patch UserPatch, newPassword []byte) (User, error) {
	if m.users == nil {
		return User{}, ErrUserInvalidInput
	}
	return m.users.UpdateUserPartial(ctx, userID, patch, newPassword)
}

// DisableUser marks a user as disabled.
func (m *Manager) DisableUser(ctx context.Context, userID string) (User, error) {
	if m.users == nil {
		return User{}, ErrUserInvalidInput
	}
	return m.users.DisableUser(ctx, userID)
}

// EnableUser re-enables a disabled user.
func (m *Manager) EnableUser(ctx context.Context, userID string) (User, error) {
	if m.users == nil {
		return User{}, ErrUserInvalidInput
	}
	return m.users.EnableUser(ctx, userID)
}

// SendPasswordReset proxies password reset flows.
func (m *Manager) SendPasswordReset(ctx context.Context, email string) (string, error) {
	if m.users == nil {
		return "", ErrResetSenderAbsent
	}
	return m.users.SendPasswordReset(ctx, email)
}
