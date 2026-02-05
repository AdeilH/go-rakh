package httpx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adeilh/go-rakh/auth"
)

func TestServerAndClientRoundTrip(t *testing.T) {
	server := NewServer()
	server.RegisterRoutes(func(a *App) {
		a.GET("/ping", func(c Context) error {
			return c.JSON(StatusOK, map[string]string{"message": "pong"})
		})
	})

	ts := NewTestServer(server.Handler())
	defer ts.Close()

	client := NewClient(WithBaseURL(ts.BaseURL()))

	var body struct {
		Message string `json:"message"`
	}
	resp, err := client.Get(context.Background(), "/ping", &body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode() != StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode())
	}
	if body.Message != "pong" {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestErrorHandlerWrapsEchoHTTPError(t *testing.T) {
	server := NewServer()
	server.RegisterRoutes(func(a *App) {
		a.GET("/fail", func(c Context) error {
			return HTTPError(StatusBadRequest, "bad request")
		})
	})

	ts := NewTestServer(server.Handler())
	defer ts.Close()

	client := NewClient(WithBaseURL(ts.BaseURL()))

	resp, err := client.Get(context.Background(), "/fail", nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if resp == nil {
		t.Fatalf("expected response for error path")
	}
	if resp.StatusCode() != StatusBadRequest {
		t.Fatalf("unexpected status: %d", resp.StatusCode())
	}
}

func TestAuthMiddlewareBridge(t *testing.T) {
	parser := &stubParser{token: stubJWT{raw: "signed"}}
	mw, err := auth.NewMiddleware(parser)
	if err != nil {
		t.Fatalf("unexpected err creating middleware: %v", err)
	}

	server := NewServer(WithMiddlewares(AuthMiddleware(mw)))
	server.RegisterRoutes(func(a *App) {
		a.GET("/secure", func(c Context) error {
			token, ok := auth.TokenFromContext(c.Request().Context())
			if !ok || token.Raw() != "signed" {
				return HTTPError(StatusUnauthorized, "missing token")
			}
			return c.JSON(StatusOK, map[string]string{"ok": "yes"})
		})
	})

	ts := NewTestServer(server.Handler())
	defer ts.Close()

	client := NewClient(WithBaseURL(ts.BaseURL()), WithHeaders(map[string]string{"Authorization": "Bearer value"}))
	var out map[string]string
	resp, err := client.Get(context.Background(), "/secure", &out, WithBearer("value"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode() != StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode())
	}
}

func TestValidatorMiddleware(t *testing.T) {
	validator := func(c Context) error {
		if c.Request().Header.Get("X-Allow") != "yes" {
			return HTTPError(StatusBadRequest, "blocked")
		}
		return nil
	}
	server := NewServer(WithValidators(validator))
	server.RegisterRoutes(func(a *App) {
		a.GET("/secure", func(c Context) error { return c.NoContent(StatusOK) })
	})

	ts := NewTestServer(server.Handler())
	defer ts.Close()

	client := NewClient(WithBaseURL(ts.BaseURL()))

	// blocked
	if _, err := client.Get(context.Background(), "/secure", nil); err == nil {
		t.Fatalf("expected validation error")
	}

	// allowed
	resp, err := client.Get(context.Background(), "/secure", nil, WithRequestHeaders(map[string]string{"X-Allow": "yes"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode() != StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode())
	}
}

func TestCORSAndLoggerInjection(t *testing.T) {
	corsCfg := DefaultCORSConfig
	corsCfg.AllowOrigins = []string{"http://example.com"}
	server := NewServer(WithCORS(&corsCfg))
	server.RegisterRoutes(func(a *App) {
		a.GET("/ping", func(c Context) error { return c.NoContent(StatusOK) })
	})

	ts := NewTestServer(server.Handler())
	defer ts.Close()

	client := NewClient(WithBaseURL(ts.BaseURL()))
	resp, err := client.Get(context.Background(), "/ping", nil, WithRequestHeaders(map[string]string{
		"Origin":                        "http://example.com",
		"Access-Control-Request-Method": "GET",
	}))
	if err != nil {
		t.Fatalf("options request failed: %v", err)
	}
	if resp.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Fatalf("expected CORS allow origin header, got %q", resp.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestRouterHelpers(t *testing.T) {
	server := NewServer()
	server.RegisterRoutes(func(a *App) {
		r := NewRouter(a, "/api")
		r.GET("/ping", func(c Context) error { return c.JSON(StatusOK, map[string]string{"message": "pong"}) })
	})

	ts := NewTestServer(server.Handler())
	defer ts.Close()

	client := NewClient(WithBaseURL(ts.BaseURL()))
	var body map[string]string
	resp, err := client.Get(context.Background(), "/api/ping", &body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode() != StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode())
	}
	if body["message"] != "pong" {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestRegisterRoutesBulkAndPostBody(t *testing.T) {
	server := NewServer()
	server.RegisterRoutes(func(a *App) {
		RegisterRoutes(a,
			Route{Method: "GET", Path: "/r1", Handler: func(c Context) error {
				return c.JSON(StatusOK, map[string]string{"route": "r1"})
			}},
			Route{Method: "POST", Path: "/echo", Handler: func(c Context) error {
				var payload map[string]any
				if err := c.Bind(&payload); err != nil {
					return HTTPError(StatusBadRequest, "invalid body")
				}
				return c.JSON(StatusCreated, payload)
			}},
		)
	})

	ts := NewTestServer(server.Handler())
	defer ts.Close()

	client := NewClient(WithBaseURL(ts.BaseURL()))

	// GET route
	var r1 map[string]string
	resp, err := client.Get(context.Background(), "/r1", &r1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode() != StatusOK || r1["route"] != "r1" {
		t.Fatalf("unexpected response: status=%d body=%v", resp.StatusCode(), r1)
	}

	// POST with JSON body
	payload := map[string]string{"hello": "world"}
	var echoed map[string]string
	resp, err = client.Post(context.Background(), "/echo", payload, &echoed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode() != StatusCreated || echoed["hello"] != "world" {
		t.Fatalf("unexpected POST response: status=%d body=%v", resp.StatusCode(), echoed)
	}
}

func TestClientRequestOptions(t *testing.T) {
	server := NewServer()
	server.RegisterRoutes(func(a *App) {
		a.GET("/opts", func(c Context) error {
			authz := c.Request().Header.Get("Authorization")
			custom := c.Request().Header.Get("X-Custom")
			qp := c.QueryParam("q")
			return c.JSON(StatusOK, map[string]string{"auth": authz, "custom": custom, "q": qp})
		})
	})

	ts := NewTestServer(server.Handler())
	defer ts.Close()

	client := NewClient(WithBaseURL(ts.BaseURL()))

	var out map[string]string
	resp, err := client.Get(context.Background(), "/opts", &out,
		WithBearer("token123"),
		WithRequestHeaders(map[string]string{"X-Custom": "yes"}),
		WithQuery(map[string]string{"q": "search"}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode() != StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode())
	}
	if out["auth"] != "Bearer token123" || out["custom"] != "yes" || out["q"] != "search" {
		t.Fatalf("unexpected headers/query: %v", out)
	}
}

func TestClientRestyConfigHook(t *testing.T) {
	server := NewServer()
	server.RegisterRoutes(func(a *App) {
		a.GET("/config", func(c Context) error {
			return c.JSON(StatusOK, map[string]string{"cfg": c.Request().Header.Get("X-Config")})
		})
	})

	ts := NewTestServer(server.Handler())
	defer ts.Close()

	client := NewClient(
		WithBaseURL(ts.BaseURL()),
		WithRestyConfig(func(rc RestClient) {
			rc.SetHeader("X-Config", "hooked")
		}),
	)

	var out map[string]string
	resp, err := client.Get(context.Background(), "/config", &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode() != StatusOK || out["cfg"] != "hooked" {
		t.Fatalf("unexpected resty config result: status=%d body=%v", resp.StatusCode(), out)
	}
}

type stubParser struct {
	token auth.JWTToken
	err   error
}

func (p *stubParser) ParseToken(_ context.Context, raw string) (auth.JWTToken, error) {
	if p.err != nil {
		return nil, p.err
	}
	if raw == "" {
		return nil, errors.New("no token")
	}
	return p.token, nil
}

type stubJWT struct {
	raw string
}

func (t stubJWT) Raw() string            { return t.raw }
func (t stubJWT) Claims() auth.JWTClaims { return auth.JWTClaims{} }
func (t stubJWT) IssuedAt() time.Time    { return time.Time{} }
func (t stubJWT) ExpiresAt() time.Time   { return time.Time{} }
