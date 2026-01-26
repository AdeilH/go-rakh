package postgrescontainer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

const (
	dockerfile    = "Dockerfile.postgres.test"
	imageName     = "go-rakh-postgres-test"
	containerName = "go-rakh-postgres-test"
	hostPort      = "55432"
	user          = "rakh"
	password      = "secret"
	dbName        = "rakh_test"
)

var (
	once     sync.Once
	setupErr error
)

// Addr returns host:port for connecting to the test Postgres instance.
func Addr() string { return "127.0.0.1:" + hostPort }

// DSN returns a lib/pq formatted connection string.
func DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", user, password, Addr(), dbName)
}

// Setup builds and launches the Postgres container if it isn't already running.
func Setup() error {
	once.Do(func() {
		if err := ensureDocker(); err != nil {
			setupErr = err
			return
		}
		_ = stopContainer()
		if err := buildImage(); err != nil {
			setupErr = err
			return
		}
		if err := runContainer(); err != nil {
			setupErr = err
			return
		}
		if err := waitForPostgres(DSN(), 10*time.Second); err != nil {
			setupErr = err
			return
		}
	})
	return setupErr
}

// Teardown stops the container launched by Setup.
func Teardown() error {
	if setupErr != nil {
		return setupErr
	}
	return stopContainer()
}

func ensureDocker() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker executable not found: %w", err)
	}
	return nil
}

func buildImage() error {
	root := repoRoot()
	dockerfilePath := filepath.Join(root, dockerfile)
	return runDocker("build", "-f", dockerfilePath, "-t", imageName, root)
}

func runContainer() error {
	return runDocker(
		"run",
		"-d",
		"--rm",
		"--name", containerName,
		"-p", fmt.Sprintf("%s:5432", hostPort),
		imageName,
	)
}

func stopContainer() error {
	cmd := exec.Command("docker", "stop", containerName)
	cmd.Dir = repoRoot()
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "No such container") {
			return nil
		}
		return fmt.Errorf("docker stop failed: %w: %s", err, output)
	}
	once = sync.Once{}
	return nil
}

func runDocker(args ...string) error {
	cmd := exec.Command("docker", args...)
	cmd.Dir = repoRoot()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker %s failed: %w: %s", args[0], err, output)
	}
	return nil
}

func waitForPostgres(dsn string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := func() error {
			db, err := sql.Open("postgres", dsn)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := db.PingContext(ctx); err != nil {
				return err
			}
			return nil
		}()
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("postgres container did not become ready in time")
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
