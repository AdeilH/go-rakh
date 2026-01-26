package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewMiddlewareRequiresParser(t *testing.T) {
	if _, err := NewMiddleware(nil); err == nil {
		t.Fatalf("expected error when parser is nil")
	}
}

func TestMiddlewareInjectsTokenIntoContext(t *testing.T) {
	parser := &fakeParser{token: stubToken{raw: "signed", claims: JWTClaims{ID: "abc"}}}
	middleware, err := NewMiddleware(parser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer source-token")
	res := httptest.NewRecorder()

	var invoked bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		invoked = true
		token, ok := TokenFromContext(r.Context())
		if !ok {
			t.Fatalf("token missing from context")
		}
		if token.Raw() != "signed" {
			t.Fatalf("unexpected token injected: %s", token.Raw())
		}
	})

	middleware.Handler(next).ServeHTTP(res, req)

	if !invoked {
		t.Fatalf("expected next handler to be invoked")
	}
	if parser.raw != "source-token" {
		t.Fatalf("parser received %q", parser.raw)
	}
}

func TestMiddlewareSkipperShortCircuits(t *testing.T) {
	parser := &fakeParser{token: stubToken{raw: "signed"}}
	middleware, err := NewMiddleware(parser, WithSkipper(func(*http.Request) bool { return true }))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()

	var invoked bool
	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		invoked = true
	})).ServeHTTP(res, req)

	if !invoked {
		t.Fatalf("expected handler invocation")
	}
	if parser.raw != "" {
		t.Fatalf("parser should not be called when skipped")
	}
}

func TestMiddlewareCustomErrorHandler(t *testing.T) {
	parser := &fakeParser{}
	var received error
	middleware, err := NewMiddleware(parser, WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		received = err
		w.WriteHeader(http.StatusTeapot)
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(res, req)

	if !errors.Is(received, ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound, got %v", received)
	}
	if res.Code != http.StatusTeapot {
		t.Fatalf("expected status 418, got %d", res.Code)
	}
}

type fakeParser struct {
	raw   string
	token JWTToken
	err   error
}

func (p *fakeParser) ParseToken(_ context.Context, raw string) (JWTToken, error) {
	p.raw = raw
	if p.err != nil {
		return nil, p.err
	}
	if p.token == nil {
		return nil, errors.New("no token configured")
	}
	return p.token, nil
}

type stubToken struct {
	raw    string
	claims JWTClaims
}

func (t stubToken) Raw() string          { return t.raw }
func (t stubToken) Claims() JWTClaims    { return t.claims }
func (t stubToken) IssuedAt() time.Time  { return time.Time{} }
func (t stubToken) ExpiresAt() time.Time { return time.Time{} }
