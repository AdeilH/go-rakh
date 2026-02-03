package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/adeilh/go-rakh/auth"
	testpg "github.com/adeilh/go-rakh/internal/testutil/postgrescontainer"
	_ "github.com/lib/pq"
)

const testTimeout = 5 * time.Second

func TestMain(m *testing.M) {
	if err := testpg.Setup(); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = testpg.Teardown()
	os.Exit(code)
}

func TestUserRepositoryCRUD(t *testing.T) {
	db := openTestDB(t)
	ensureSchema(t, db)
	repo := NewUserRepository(db)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	user := auth.User{
		ID:    "11111111-1111-1111-1111-111111111111",
		Email: "test@example.com",
		Name:  "Test User",
		Title: "Ms",
		PasswordHash: auth.PasswordHash{
			Algorithm: "bcrypt",
			Cost:      10,
			Salt:      []byte("salt"),
			Value:     []byte("hash"),
			CreatedAt: time.Now().UTC(),
		},
		Metadata:  map[string]string{"role": "admin"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if err := repo.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser error: %v", err)
	}

	fetched, err := repo.GetUserByEmail(ctx, user.Email)
	if err != nil {
		t.Fatalf("GetUserByEmail error: %v", err)
	}

	if fetched.Email != user.Email {
		t.Fatalf("expected email %s got %s", user.Email, fetched.Email)
	}

	fetched.Metadata["role"] = "user"
	fetched.PasswordHash.Value = []byte("hash2")
	fetched.UpdatedAt = time.Now().UTC()

	if err := repo.UpdateUser(ctx, fetched); err != nil {
		t.Fatalf("UpdateUser error: %v", err)
	}

	// Partial update only metadata
	patch := auth.UserPatch{Metadata: map[string]string{"team": "blue"}}
	updated, err := repo.UpdateUserPartial(ctx, fetched.ID, patch)
	if err != nil {
		t.Fatalf("UpdateUserPartial error: %v", err)
	}

	if updated.Metadata["team"] != "blue" {
		t.Fatalf("expected team=blue got %s", updated.Metadata["team"])
	}

	// Disable then enable
	disabledUser, err := repo.DisableUser(ctx, fetched.ID)
	if err != nil {
		t.Fatalf("DisableUser error: %v", err)
	}
	if disabledUser.Enabled {
		t.Fatalf("expected user to be disabled")
	}

	enabledUser, err := repo.EnableUser(ctx, fetched.ID)
	if err != nil {
		t.Fatalf("EnableUser error: %v", err)
	}
	if !enabledUser.Enabled {
		t.Fatalf("expected user to be enabled")
	}

	final, err := repo.GetUserByEmail(ctx, user.Email)
	if err != nil {
		t.Fatalf("GetUserByEmail after enable error: %v", err)
	}

	if final.Metadata["role"] != "user" {
		t.Fatalf("expected updated role user got %s", final.Metadata["role"])
	}

	if _, err := repo.DisableUser(ctx, "missing-id"); err != auth.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound on missing disable got %v", err)
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", testpg.DSN())
	if err != nil {
		t.Fatalf("sql.Open error: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("db.Ping error: %v", err)
	}
	return db
}

func ensureSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	statements := []string{
		"CREATE EXTENSION IF NOT EXISTS citext",
		"DROP TABLE IF EXISTS users",
		auth.DefaultUserTableSchema,
	}
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec schema statement failed: %v", err)
		}
	}
}
