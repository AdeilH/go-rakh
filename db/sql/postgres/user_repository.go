package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/adeilh/go-rakh/auth"
	"github.com/lib/pq"
)

// UserRepository persists auth.User records inside PostgreSQL.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository wraps an existing *sql.DB connection.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(ctx context.Context, user auth.User) error {
	const query = `INSERT INTO users (id, email, name, title, password_hash, metadata, enabled, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	hashJSON, metadataJSON, err := marshalUserFields(user)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, query, user.ID, user.Email, user.Name, user.Title, hashJSON, metadataJSON, user.Enabled, user.CreatedAt, user.UpdatedAt)
	return translateUserError(err)
}

func (r *UserRepository) UpdateUser(ctx context.Context, user auth.User) error {
	const query = `UPDATE users SET email = $2, name = $3, title = $4, password_hash = $5, metadata = $6, enabled = $7, updated_at = $8 WHERE id = $1`
	hashJSON, metadataJSON, err := marshalUserFields(user)
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, query, user.ID, user.Email, user.Name, user.Title, hashJSON, metadataJSON, user.Enabled, user.UpdatedAt)
	if err != nil {
		return translateUserError(err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

// UpdateUserPartial applies a patch onto an existing user.
func (r *UserRepository) UpdateUserPartial(ctx context.Context, userID string, patch auth.UserPatch) (auth.User, error) {
	existing, err := r.getUserByID(ctx, userID)
	if err != nil {
		return auth.User{}, err
	}

	if patch.Email != nil {
		existing.Email = *patch.Email
	}
	if patch.PasswordHash != nil {
		existing.PasswordHash = *patch.PasswordHash
	}
	if patch.Name != nil {
		existing.Name = *patch.Name
	}
	if patch.Title != nil {
		existing.Title = *patch.Title
	}
	if patch.Metadata != nil {
		if existing.Metadata == nil {
			existing.Metadata = make(map[string]string, len(patch.Metadata))
		}
		for k, v := range patch.Metadata {
			existing.Metadata[k] = v
		}
	}
	if patch.Enabled != nil {
		existing.Enabled = *patch.Enabled
	}

	existing.UpdatedAt = time.Now().UTC()

	if err := r.UpdateUser(ctx, existing); err != nil {
		return auth.User{}, err
	}
	return existing, nil
}

// DisableUser marks a user as disabled via metadata.
func (r *UserRepository) DisableUser(ctx context.Context, userID string) (auth.User, error) {
	return r.toggleDisable(ctx, userID, true)
}

// EnableUser removes the disabled flag.
func (r *UserRepository) EnableUser(ctx context.Context, userID string) (auth.User, error) {
	return r.toggleDisable(ctx, userID, false)
}

func (r *UserRepository) toggleDisable(ctx context.Context, userID string, disabled bool) (auth.User, error) {
	user, err := r.getUserByID(ctx, userID)
	if err != nil {
		return auth.User{}, err
	}
	user.Enabled = !disabled
	user.UpdatedAt = time.Now().UTC()
	if err := r.UpdateUser(ctx, user); err != nil {
		return auth.User{}, err
	}
	return user, nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (auth.User, error) {
	const query = `SELECT id, email, name, title, password_hash, metadata, enabled, created_at, updated_at FROM users WHERE email = $1`
	var (
		hashJSON     []byte
		metadataJSON []byte
		user         auth.User
	)
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.Title,
		&hashJSON,
		&metadataJSON,
		&user.Enabled,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.User{}, auth.ErrUserNotFound
		}
		return auth.User{}, translateUserError(err)
	}
	if err := json.Unmarshal(hashJSON, &user.PasswordHash); err != nil {
		return auth.User{}, err
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
			return auth.User{}, err
		}
	}
	return user, nil
}

func (r *UserRepository) getUserByID(ctx context.Context, id string) (auth.User, error) {
	const query = `SELECT id, email, name, title, password_hash, metadata, enabled, created_at, updated_at FROM users WHERE id = $1`
	var (
		hashJSON     []byte
		metadataJSON []byte
		user         auth.User
	)
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.Title,
		&hashJSON,
		&metadataJSON,
		&user.Enabled,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.User{}, auth.ErrUserNotFound
		}
		return auth.User{}, translateUserError(err)
	}
	if err := json.Unmarshal(hashJSON, &user.PasswordHash); err != nil {
		return auth.User{}, err
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
			return auth.User{}, err
		}
	}
	return user, nil
}

func marshalUserFields(user auth.User) ([]byte, []byte, error) {
	hashJSON, err := json.Marshal(user.PasswordHash)
	if err != nil {
		return nil, nil, err
	}
	metadataJSON, err := json.Marshal(user.Metadata)
	if err != nil {
		return nil, nil, err
	}
	return hashJSON, metadataJSON, nil
}

func translateUserError(err error) error {
	if err == nil {
		return nil
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505":
			return auth.ErrUserEmailInUse
		case "22P02":
			return auth.ErrUserNotFound
		}
	}
	return err
}
