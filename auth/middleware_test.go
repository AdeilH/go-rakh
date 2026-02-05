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

func TestMiddlewareHandlerNilNext(t *testing.T) {
	parser := &fakeParser{token: stubToken{raw: "token"}}
	middleware, _ := NewMiddleware(parser, WithSkipper(func(*http.Request) bool { return true }))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()

	// Should not panic with nil next
	middleware.Handler(nil).ServeHTTP(res, req)
}

func TestMiddlewareHandlerPanicsOnNilMiddleware(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil middleware")
		}
	}()

	var m *Middleware
	m.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
}

func TestMiddlewareExtractorError(t *testing.T) {
	parser := &fakeParser{token: stubToken{raw: "token"}}
	middleware, _ := NewMiddleware(parser, WithTokenExtractor(func(r *http.Request) (string, error) {
		return "", errors.New("extractor error")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()

	var handlerCalled bool
	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalled = true
	})).ServeHTTP(res, req)

	if handlerCalled {
		t.Error("handler should not be called when extractor fails")
	}
	if res.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", res.Code)
	}
}

func TestMiddlewareParserError(t *testing.T) {
	parser := &fakeParser{err: errors.New("parse error")}
	middleware, _ := NewMiddleware(parser)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	res := httptest.NewRecorder()

	var handlerCalled bool
	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalled = true
	})).ServeHTTP(res, req)

	if handlerCalled {
		t.Error("handler should not be called when parser fails")
	}
}

func TestTokenFromContextNil(t *testing.T) {
	token, ok := TokenFromContext(nil)
	if ok {
		t.Error("expected false for nil context")
	}
	if token != nil {
		t.Error("expected nil token for nil context")
	}
}

func TestTokenFromContextMissing(t *testing.T) {
	ctx := context.Background()
	token, ok := TokenFromContext(ctx)
	if ok {
		t.Error("expected false for context without token")
	}
	if token != nil {
		t.Error("expected nil token")
	}
}

func TestTokenFromContextWrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), tokenContextKey, "not-a-token")
	token, ok := TokenFromContext(ctx)
	if ok {
		t.Error("expected false for wrong type")
	}
	if token != nil {
		t.Error("expected nil token for wrong type")
	}
}

func TestMiddlewarePathBasedSkipper(t *testing.T) {
	parser := &fakeParser{token: stubToken{raw: "token"}}
	
	skipper := func(r *http.Request) bool {
		return r.URL.Path == "/health" || r.URL.Path == "/metrics"
	}
	
	middleware, _ := NewMiddleware(parser, WithSkipper(skipper))

	tests := []struct {
		path        string
		wantSkipped bool
	}{
		{"/health", true},
		{"/metrics", true},
		{"/api/users", false},
		{"/", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if !tt.wantSkipped {
				req.Header.Set("Authorization", "Bearer token")
			}
			res := httptest.NewRecorder()

			var handlerCalled bool
			middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				handlerCalled = true
			})).ServeHTTP(res, req)

			if !handlerCalled {
				if tt.wantSkipped {
					t.Error("handler should be called when skipped")
				}
			}
		})
	}
}

func TestMiddlewareMethodBasedSkipper(t *testing.T) {
	parser := &fakeParser{token: stubToken{raw: "token"}}
	
	skipper := func(r *http.Request) bool {
		return r.Method == http.MethodOptions
	}
	
	middleware, _ := NewMiddleware(parser, WithSkipper(skipper))

	tests := []struct {
		method      string
		wantSkipped bool
	}{
		{http.MethodOptions, true},
		{http.MethodGet, false},
		{http.MethodPost, false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", nil)
			if !tt.wantSkipped {
				req.Header.Set("Authorization", "Bearer token")
			}
			res := httptest.NewRecorder()

			var handlerCalled bool
			middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				handlerCalled = true
			})).ServeHTTP(res, req)

			if !handlerCalled && tt.wantSkipped {
				t.Error("handler should be called when skipped")
			}
		})
	}
}

func TestMiddlewareCookieExtractor(t *testing.T) {
	parser := &fakeParser{token: stubToken{raw: "token", claims: JWTClaims{Subject: "user"}}}
	middleware, _ := NewMiddleware(parser, WithTokenExtractor(CookieTokenExtractor("auth")))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: "cookie-token"})
	res := httptest.NewRecorder()

	var tokenFromCtx JWTToken
	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenFromCtx, _ = TokenFromContext(r.Context())
	})).ServeHTTP(res, req)

	if tokenFromCtx == nil {
		t.Fatal("token not injected into context")
	}
	if parser.raw != "cookie-token" {
		t.Errorf("parser received %q, want %q", parser.raw, "cookie-token")
	}
}

func TestMiddlewareChainedExtractor(t *testing.T) {
	parser := &fakeParser{token: stubToken{raw: "token"}}
	extractor := ChainExtractors(
		BearerTokenExtractor(),
		CookieTokenExtractor("auth"),
	)
	middleware, _ := NewMiddleware(parser, WithTokenExtractor(extractor))

	t.Run("header first", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer header-token")
		req.AddCookie(&http.Cookie{Name: "auth", Value: "cookie-token"})
		res := httptest.NewRecorder()

		middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(res, req)

		if parser.raw != "header-token" {
			t.Errorf("should use header token first, got %q", parser.raw)
		}
	})

	t.Run("fallback to cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "auth", Value: "cookie-token"})
		res := httptest.NewRecorder()

		middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(res, req)

		if parser.raw != "cookie-token" {
			t.Errorf("should fallback to cookie, got %q", parser.raw)
		}
	})
}

func TestMiddlewareContextPropagation(t *testing.T) {
	parser := &fakeParser{token: stubToken{
		raw: "token",
		claims: JWTClaims{
			ID:        "token-id-123",
			Subject:   "user-456",
			Issuer:    "test-issuer",
			Metadata:  map[string]any{"role": "admin"},
		},
	}}
	middleware, _ := NewMiddleware(parser)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	res := httptest.NewRecorder()

	var capturedToken JWTToken
	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedToken, _ = TokenFromContext(r.Context())
	})).ServeHTTP(res, req)

	if capturedToken == nil {
		t.Fatal("token not in context")
	}
	if capturedToken.Claims().ID != "token-id-123" {
		t.Errorf("ID = %s, want token-id-123", capturedToken.Claims().ID)
	}
	if capturedToken.Claims().Subject != "user-456" {
		t.Errorf("Subject = %s, want user-456", capturedToken.Claims().Subject)
	}
	if capturedToken.Claims().Metadata["role"] != "admin" {
		t.Error("Metadata not preserved")
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
