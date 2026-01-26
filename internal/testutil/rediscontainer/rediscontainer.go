package rediscontainer

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	dockerfile    = "Dockerfile.redis.test"
	imageName     = "go-rakh-cache-redis-test"
	containerName = "go-rakh-cache-redis-test"
	hostPort      = "6390"
)

var (
	once     sync.Once
	setupErr error
)

// Addr exposes the Redis host:port combination used by integration tests.
func Addr() string { return "127.0.0.1:" + hostPort }

// Setup builds the Redis test image, runs the container, and waits until it
// answers RESP PING/PONG exchanges.
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
		if err := waitForRedis(Addr(), 5*time.Second); err != nil {
			setupErr = err
			return
		}
	})
	return setupErr
}

// Teardown stops the Redis container if it is running.
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
		"-p", fmt.Sprintf("%s:6379", hostPort),
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

func waitForRedis(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	payload := []byte("*1\r\n$4\r\nPING\r\n")
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			if _, err := conn.Write(payload); err == nil {
				_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				reader := bufio.NewReader(conn)
				line, err := reader.ReadString('\n')
				if err == nil && strings.Contains(line, "PONG") {
					_ = conn.Close()
					return nil
				}
			}
			_ = conn.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("redis container did not respond to ping")
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
