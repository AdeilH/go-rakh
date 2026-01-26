package redis

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adeilh/go-rakh/cache"
	testredis "github.com/adeilh/go-rakh/internal/testutil/rediscontainer"
)

func TestMain(m *testing.M) {
	if err := testredis.Setup(); err != nil {
		fmt.Println("redis cache tests skipped:", err)
		os.Exit(0)
	}

	code := m.Run()

	if err := testredis.Teardown(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to stop redis test container:", err)
	}

	os.Exit(code)
}

func TestStoreSetGetDelete(t *testing.T) {
	store := NewStore(Options{Addr: testredis.Addr()})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	key := fmt.Sprintf("redis:test:%d", time.Now().UnixNano())
	value := []byte("some-payload")

	if err := store.Set(ctx, key, value, 0); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	payload, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if string(payload) != string(value) {
		t.Fatalf("Get() = %q, want %q", payload, value)
	}

	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if _, err := store.Get(ctx, key); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStoreTTL(t *testing.T) {
	store := NewStore(Options{Addr: testredis.Addr()})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := fmt.Sprintf("redis:ttl:%d", time.Now().UnixNano())
	ttl := 200 * time.Millisecond

	if err := store.Set(ctx, key, []byte("value"), ttl); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	time.Sleep(ttl + 100*time.Millisecond)

	if _, err := store.Get(ctx, key); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after TTL, got %v", err)
	}
}

func TestStoreContextCancellation(t *testing.T) {
	store := NewStore(Options{Addr: testredis.Addr()})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := store.Set(ctx, "any", []byte("value"), 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestStoreConcurrentSetGet(t *testing.T) {
	store := NewStore(Options{Addr: testredis.Addr()})

	const workers = 32
	const opsPerWorker = 100

	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				key := fmt.Sprintf("redis:concurrent:%d:%d", worker, i)
				val := []byte(key)

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				if err := store.Set(ctx, key, val, time.Second); err != nil {
					errCh <- fmt.Errorf("worker %d set failed: %w", worker, err)
					cancel()
					return
				}
				payload, err := store.Get(ctx, key)
				cancel()
				if err != nil {
					errCh <- fmt.Errorf("worker %d get failed: %w", worker, err)
					return
				}
				if string(payload) != string(val) {
					errCh <- fmt.Errorf("worker %d mismatch: got %q want %q", worker, payload, val)
					return
				}
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent op failed: %v", err)
	}
}

func TestStorePipeline(t *testing.T) {
	store := NewStore(Options{Addr: testredis.Addr()})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pipeline, err := store.Pipeline(ctx)
	if err != nil {
		t.Fatalf("Pipeline() error = %v", err)
	}
	defer pipeline.Close()

	key1 := fmt.Sprintf("redis:pipeline:%d:1", time.Now().UnixNano())
	key2 := fmt.Sprintf("redis:pipeline:%d:2", time.Now().UnixNano())

	pipeline.Queue("SET", key1, "v1")
	pipeline.Queue("SET", key2, "v2")
	pipeline.Queue("MGET", key1, key2)

	responses, err := pipeline.Exec(ctx)
	if err != nil {
		t.Fatalf("Exec() error = %v", err)
	}

	if len(responses) != 3 {
		t.Fatalf("expected 3 responses, got %d", len(responses))
	}

	if msg, _ := responses[0].(string); !strings.EqualFold(msg, "OK") {
		t.Fatalf("first response = %v, want OK", responses[0])
	}
	if msg, _ := responses[1].(string); !strings.EqualFold(msg, "OK") {
		t.Fatalf("second response = %v, want OK", responses[1])
	}

	values, ok := responses[2].([]any)
	if !ok {
		t.Fatalf("expected array response, got %T", responses[2])
	}
	if string(values[0].([]byte)) != "v1" || string(values[1].([]byte)) != "v2" {
		t.Fatalf("unexpected MGET payload: %v", values)
	}
}
