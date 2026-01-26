package auth

import (
	"context"
	"time"
)

// JWTClaims models the payload embedded inside a signed JWT.
type JWTClaims struct {
	ID        string
	Subject   string
	Issuer    string
	Audience  []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	NotBefore time.Time
	Metadata  map[string]any
}

// JWTOptions captures the knobs available when minting JWTs.
type JWTOptions struct {
	Issuer    string
	Audience  []string
	TTL       time.Duration
	ClockSkew time.Duration
	KeyID     string
	Algorithm string
}

// JWTToken exposes immutable information about a minted JWT.
type JWTToken interface {
	Raw() string
	Claims() JWTClaims
	IssuedAt() time.Time
	ExpiresAt() time.Time
}

// JWTTokenProvider issues, validates, and revokes JWTs.
type JWTTokenProvider interface {
	Issue(ctx context.Context, claims JWTClaims, opts JWTOptions) (JWTToken, error)
	Parse(ctx context.Context, raw string) (JWTToken, error)
	Revoke(ctx context.Context, tokenID string) error
}

// SessionDescriptor represents the persisted shape of a session token.
type SessionDescriptor struct {
	ID        string
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
	Metadata  map[string]string
}

// SessionToken surfaces runtime helpers for issued sessions.
type SessionToken interface {
	Descriptor() SessionDescriptor
	IsExpired(at time.Time) bool
}

// SessionStore persists session tokens and supports lifecycle management.
type SessionStore interface {
	Create(ctx context.Context, desc SessionDescriptor) (SessionToken, error)
	Get(ctx context.Context, id string) (SessionToken, error)
	Delete(ctx context.Context, id string) error
	Touch(ctx context.Context, id string, expiresAt time.Time) error
}

// PasswordHash contains the metadata needed to verify a hashed password.
type PasswordHash struct {
	Algorithm string
	Cost      int
	Salt      []byte
	Value     []byte
	CreatedAt time.Time
}

// PasswordOptions defines how new passwords should be hashed.
type PasswordOptions struct {
	Algorithm  string
	SaltLength int
	Cost       int
	Pepper     []byte
	MaxAge     time.Duration
}

// PasswordHasher manages password hashing and verification.
type PasswordHasher interface {
	Hash(ctx context.Context, plain []byte, opts PasswordOptions) (PasswordHash, error)
	Compare(ctx context.Context, plain []byte, hash PasswordHash) error
	NeedsRehash(hash PasswordHash, opts PasswordOptions) bool
}
