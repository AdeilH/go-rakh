package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// ApplyMigrations executes the provided SQL statements in order within the given context.
func ApplyMigrations(ctx context.Context, db *sql.DB, statements ...string) error {
	if db == nil {
		return fmt.Errorf("postgres: db is nil")
	}
	for _, stmt := range statements {
		if stmt == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("postgres: migrate: %w", err)
		}
	}
	return nil
}
