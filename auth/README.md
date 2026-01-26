# Auth Module Guide

This guide shows how to integrate the Go Rakh auth stack (JWT, sessions, password hashing, and user CRUD) into your own services.

## Components
- `JWTTokenProvider`: Issues, parses, and revokes HMAC-based JWTs.
- `SessionStore`: Persists session descriptors inside any `cache.Store` (Redis provided).
- `PasswordHasher`: Abstract interface (plug in bcrypt/argon2, etc.).
- `UserService`: Wraps the hasher and repository to manage users + reset flows.
- `Manager`: High-level façade exposing CRUD-style helpers for tokens, sessions, and users.

## Prerequisites
- Go 1.21+
- Docker (for running Redis/Postgres during development/testing)

## 1. Bring up Redis (cache store)
```bash
# Build and run the disposable Redis instance used in tests
docker build -f Dockerfile.redis.test -t go-rakh-redis-test .
docker run -d --rm --name go-rakh-redis -p 6390:6379 go-rakh-redis-test
```
Then create a cache store:
```go
import (
    "github.com/adeilh/go-rakh/cache/redis"
)

store := redis.NewStore(redis.Options{Addr: "127.0.0.1:6390"})
```
Reuse this `store` for both JWTs and sessions to keep everything consistent.

## 2. Prepare Postgres (user repository)
```bash
# Build and run the disposable Postgres instance (user/password from Dockerfile.postgres.test)
docker build -f Dockerfile.postgres.test -t go-rakh-postgres-test .
docker run -d --rm --name go-rakh-postgres -p 55432:5432 go-rakh-postgres-test
```
Apply the default schema (note the `enabled` column defaults to true):
```sql
CREATE EXTENSION IF NOT EXISTS citext;
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email CITEXT UNIQUE NOT NULL,
    password_hash JSONB NOT NULL,
    metadata JSONB,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
```
Instantiate the repository:
```go
import (
    "database/sql"
    _ "github.com/lib/pq"
    dbpg "github.com/adeilh/go-rakh/db/sql/postgres"
)

dsn := "postgres://rakh:secret@127.0.0.1:55432/rakh_test?sslmode=disable"
db, err := sql.Open("postgres", dsn)
repo := dbpg.NewUserRepository(db)
```

## 3. Wire up the auth.Manager
```go
import (
    "context"
    "time"

    "github.com/adeilh/go-rakh/auth"
)

hasher := auth.NewBcryptHasher() // implement auth.PasswordHasher
manager, err := auth.NewManager(auth.ManagerConfig{
    Cache:         store,
    JWTSecret:     []byte("super-secret"),
    JWTAlgorithms: []string{"HS256"},
    SessionOptions: auth.SessionStoreOptions{
        Prefix:     "session",
        DefaultTTL: 24 * time.Hour,
    },
    UserRepository: repo,
    PasswordHasher: hasher,
})
if err != nil { /* handle */ }

ctx := context.Background()
// 1) Create user
user, err := manager.CreateUser(ctx, "user@example.com", []byte("password"), map[string]string{"role": "admin"})
// 2) Issue JWT
jwt, err := manager.IssueToken(ctx, auth.JWTClaims{Subject: user.ID}, auth.JWTOptions{Issuer: "api", TTL: time.Hour})
// 3) Create session
session, err := manager.CreateSession(ctx, auth.SessionDescriptor{Subject: user.ID})
```

## 4. Running tests
```bash
# Auth unit + integration tests (spins up Redis automatically)
go test ./auth

# Postgres repository tests (Dockerized Postgres)
go test ./db/sql/postgres
```

## 5. Password resets
Implement `auth.PasswordResetSender` (e.g., email or SMS) and pass it into `ManagerConfig`. Then call:
```go
if _, err := manager.SendPasswordReset(ctx, "user@example.com"); err != nil {
    // handle
}
```
The service will fetch the user, generate a random token via `TokenFactory`, and hand it to your sender.

## Notes
- Currently Redis and Postgres are the supported production-ready backends; memory/MySQL adapters are marked TODO.
- The `examples/` folder shows how to embed the manager inside a full HTTP server.
- Feel free to fork/extend the cache or repo interfaces for custom infrastructure.
- Use `manager.DisableUser` / `manager.EnableUser` to soft-disable via the `enabled` column instead of deleting rows.
