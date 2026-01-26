package postgres

import (
	"context"
	"database/sql"
)

// Connect opens a PostgreSQL connection using the provided options.
func Connect(opts ...Option) (*sql.DB, error) {
	return Open(opts...)
}

// Migrate applies the given statements using the provided context.
func Migrate(ctx context.Context, db *sql.DB, statements ...string) error {
	return ApplyMigrations(ctx, db, statements...)
}
