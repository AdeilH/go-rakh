# httpx Server and Client Guide

This guide shows how to stand up an Echo-powered server and call it with the bundled Resty-based client using only `httpx` APIs.

## Install
```bash
# from a module that depends on go-rakh
go get github.com/adeilh/go-rakh/httpx
```
If you use a local checkout with `go.work`, keep the replace in your workspace as needed.

## Server setup
```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/adeilh/go-rakh/httpx"
)

func main() {
    srv := httpx.NewServer(
        httpx.WithAddress(":8080"),
        httpx.WithMiddlewares(httpx.LoggerMiddleware(), httpx.RecoverMiddleware()),
        httpx.WithCORS(nil), // default CORS, omit if not needed
        httpx.WithValidators(func(c httpx.Context) error {
            if c.Request().Header.Get("X-Trace") == "" {
                return httpx.HTTPError(httpx.StatusBadRequest, "missing trace id")
            }
            return nil
        }),
    )

    srv.RegisterRoutes(func(e *httpx.Echo) {
        e.GET("/health", func(c httpx.Context) error {
            return c.NoContent(httpx.StatusOK)
        })

        api := httpx.NewRouter(e, "/api")
        api.GET("/hello", func(c httpx.Context) error {
            return c.JSON(httpx.StatusOK, map[string]string{"message": "hi"})
        })
    })

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Start is blocking; cancel the context to stop with graceful shutdown.
    if err := srv.Start(ctx, httpx.WithShutdownTimeout(5*time.Second)); err != nil {
        log.Fatal(err)
    }
}
```

### Server options recap
- `WithAddress(addr)` — bind address (default `:8080`).
- `WithTimeouts(read, write)` — server read/write timeouts.
- `WithMiddlewares(...)` / `AppendMiddlewares(...)` — global middleware stack.
- `WithValidators(...)` — request validators that run before handlers.
- `WithCORS(cfg)` — enable CORS (`nil` uses Echo defaults).
- `WithErrorHandler(handler)` — override default JSON error handler.
- `WithLogger(logger)` — plug a custom Echo logger.
- `WithShutdownTimeout(d)` — per-start graceful shutdown timeout.

## Client setup
```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/adeilh/go-rakh/httpx"
)

func main() {
    cli := httpx.NewClient(
        httpx.WithBaseURL("http://localhost:8080"),
        httpx.WithClientTimeout(5*time.Second),
        httpx.WithHeaders(map[string]string{"X-Caller": "demo"}),
        httpx.WithRestyConfig(func(r httpx.RestClient) { r.SetTimeout(3 * time.Second) }),
    )

    var respBody map[string]string
    if _, err := cli.Get(context.Background(), "/api/hello", &respBody, httpx.WithBearer("token-here")); err != nil {
        log.Fatal(err)
    }
    log.Printf("response: %+v", respBody)
}
```

### Request helpers
- `cli.Get(ctx, path, result, opts...)`
- `cli.Post(ctx, path, body, result, opts...)`
- `cli.Put(ctx, path, body, result, opts...)`
- `cli.Delete(ctx, path, result, opts...)`

Common options:
- `WithQuery(map[string]string)` — query parameters.
- `WithRequestHeaders(map[string]string)` — per-request headers.
- `WithBearer(token)` — sets `Authorization: Bearer ...`.

Errors: non-2xx responses return `err` like `"http 400: <body>"` and `resp.IsError()` is true.

## Testing server + client together
```go
package httpx_test

import (
    "context"
    "net/http"
    "testing"
    "time"

    "github.com/adeilh/go-rakh/httpx"
)

func TestServerAndClient(t *testing.T) {
    srv := httpx.NewServer(httpx.WithAddress("127.0.0.1:0"))
    srv.RegisterRoutes(func(e *httpx.Echo) {
        e.GET("/hello", func(c httpx.Context) error { return c.String(httpx.StatusOK, "ok") })
    })

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    go func() { _ = srv.Start(ctx) }()

    // Give the server a moment to bind
    time.Sleep(100 * time.Millisecond)

    // The Echo instance holds the active address once started.
    addr := srv.Handler().(*httpx.Echo).Server.Addr
    cli := httpx.NewClient(httpx.WithBaseURL("http://" + addr))

    resp, err := cli.Get(context.Background(), "/hello", nil)
    if err != nil {
        t.Fatalf("request failed: %v", err)
    }
    if resp.StatusCode() != http.StatusOK {
        t.Fatalf("want 200 got %d", resp.StatusCode())
    }
}
```

## Status code guidance (see `status.go`)
- `StatusOK`, `StatusCreated`, `StatusNoContent` — success.
- `StatusBadRequest` — validation/shape errors.
- `StatusUnauthorized` / `StatusForbidden` — auth/authz failures.
- `StatusNotFound` — missing resources.
- `StatusConflict`, `StatusUnprocessableEntity`, `StatusTooManyRequests` — conflict, semantic validation, throttling.
- `StatusInternalError`, `StatusServiceUnavailable` — server or dependency failures.

## Quick commands
```bash
# Run httpx tests
cd httpx
go test ./...
```
