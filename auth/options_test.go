package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerTokenExtractor(t *testing.T) {
	extractor := BearerTokenExtractor()

	tests := []struct {
		name       string
		header     string
		wantToken  string
		wantErr    error
	}{
		{
			name:      "valid bearer token",
			header:    "Bearer my-token-123",
			wantToken: "my-token-123",
			wantErr:   nil,
		},
		{
			name:      "lowercase bearer",
			header:    "bearer my-token",
			wantToken: "my-token",
			wantErr:   nil,
		},
		{
			name:      "mixed case bearer",
			header:    "BEARER MY-TOKEN",
			wantToken: "MY-TOKEN",
			wantErr:   nil,
		},
		{
			name:      "empty header",
			header:    "",
			wantToken: "",
			wantErr:   ErrTokenNotFound,
		},
		{
			name:      "no space after bearer",
			header:    "Bearertoken",
			wantToken: "",
			wantErr:   ErrTokenInvalidInput,
		},
		{
			name:      "basic auth",
			header:    "Basic dXNlcjpwYXNz",
			wantToken: "",
			wantErr:   ErrTokenInvalidInput,
		},
		{
			name:      "bearer with empty token",
			header:    "Bearer ",
			wantToken: "",
			wantErr:   ErrTokenInvalidInput,
		},
		{
			name:      "bearer with spaces only",
			header:    "Bearer    ",
			wantToken: "",
			wantErr:   ErrTokenInvalidInput,
		},
		{
			name:      "token with extra spaces",
			header:    "Bearer   my-token   ",
			wantToken: "my-token",
			wantErr:   nil,
		},
		{
			name:      "just bearer word",
			header:    "Bearer",
			wantToken: "",
			wantErr:   ErrTokenInvalidInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			token, err := extractor(req)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("BearerTokenExtractor() error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("BearerTokenExtractor() unexpected error = %v", err)
			}
			if token != tt.wantToken {
				t.Errorf("BearerTokenExtractor() token = %q, want %q", token, tt.wantToken)
			}
		})
	}
}

func TestCookieTokenExtractor(t *testing.T) {
	t.Run("valid cookie", func(t *testing.T) {
		extractor := CookieTokenExtractor("auth_token")
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: "my-token"})

		token, err := extractor(req)
		if err != nil {
			t.Errorf("CookieTokenExtractor() error = %v", err)
		}
		if token != "my-token" {
			t.Errorf("CookieTokenExtractor() token = %q, want %q", token, "my-token")
		}
	})

	t.Run("missing cookie", func(t *testing.T) {
		extractor := CookieTokenExtractor("auth_token")
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		_, err := extractor(req)
		if !errors.Is(err, ErrTokenNotFound) {
			t.Errorf("CookieTokenExtractor() error = %v, want ErrTokenNotFound", err)
		}
	})

	t.Run("empty cookie name", func(t *testing.T) {
		extractor := CookieTokenExtractor("")
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		_, err := extractor(req)
		if !errors.Is(err, ErrTokenInvalidInput) {
			t.Errorf("CookieTokenExtractor() error = %v, want ErrTokenInvalidInput", err)
		}
	})

	t.Run("whitespace cookie name", func(t *testing.T) {
		extractor := CookieTokenExtractor("   ")
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		_, err := extractor(req)
		if !errors.Is(err, ErrTokenInvalidInput) {
			t.Errorf("CookieTokenExtractor() error = %v, want ErrTokenInvalidInput", err)
		}
	})

	t.Run("empty cookie value", func(t *testing.T) {
		extractor := CookieTokenExtractor("auth_token")
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: ""})

		_, err := extractor(req)
		if !errors.Is(err, ErrTokenInvalidInput) {
			t.Errorf("CookieTokenExtractor() error = %v, want ErrTokenInvalidInput", err)
		}
	})

	t.Run("whitespace only cookie value", func(t *testing.T) {
		extractor := CookieTokenExtractor("auth_token")
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: "   "})

		_, err := extractor(req)
		if !errors.Is(err, ErrTokenInvalidInput) {
			t.Errorf("CookieTokenExtractor() error = %v, want ErrTokenInvalidInput", err)
		}
	})

	t.Run("trims whitespace from value", func(t *testing.T) {
		extractor := CookieTokenExtractor("auth_token")
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: "  my-token  "})

		token, err := extractor(req)
		if err != nil {
			t.Errorf("CookieTokenExtractor() error = %v", err)
		}
		if token != "my-token" {
			t.Errorf("CookieTokenExtractor() token = %q, want %q", token, "my-token")
		}
	})
}

func TestChainExtractors(t *testing.T) {
	t.Run("first extractor succeeds", func(t *testing.T) {
		extractor := ChainExtractors(
			BearerTokenExtractor(),
			CookieTokenExtractor("token"),
		)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer header-token")
		req.AddCookie(&http.Cookie{Name: "token", Value: "cookie-token"})

		token, err := extractor(req)
		if err != nil {
			t.Errorf("ChainExtractors() error = %v", err)
		}
		if token != "header-token" {
			t.Errorf("ChainExtractors() token = %q, want %q", token, "header-token")
		}
	})

	t.Run("fallback to second extractor", func(t *testing.T) {
		extractor := ChainExtractors(
			BearerTokenExtractor(),
			CookieTokenExtractor("token"),
		)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: "cookie-token"})

		token, err := extractor(req)
		if err != nil {
			t.Errorf("ChainExtractors() error = %v", err)
		}
		if token != "cookie-token" {
			t.Errorf("ChainExtractors() token = %q, want %q", token, "cookie-token")
		}
	})

	t.Run("all extractors fail", func(t *testing.T) {
		extractor := ChainExtractors(
			BearerTokenExtractor(),
			CookieTokenExtractor("token"),
		)

		req := httptest.NewRequest(http.MethodGet, "/", nil)

		_, err := extractor(req)
		if err == nil {
			t.Error("ChainExtractors() should return error when all fail")
		}
	})

	t.Run("empty chain", func(t *testing.T) {
		extractor := ChainExtractors()
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		_, err := extractor(req)
		if !errors.Is(err, ErrTokenNotFound) {
			t.Errorf("ChainExtractors() error = %v, want ErrTokenNotFound", err)
		}
	})

	t.Run("nil extractors in chain", func(t *testing.T) {
		extractor := ChainExtractors(
			nil,
			BearerTokenExtractor(),
			nil,
		)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer my-token")

		token, err := extractor(req)
		if err != nil {
			t.Errorf("ChainExtractors() error = %v", err)
		}
		if token != "my-token" {
			t.Errorf("ChainExtractors() token = %q, want %q", token, "my-token")
		}
	})
}

func TestMiddlewareOptions(t *testing.T) {
	mockParser := &fakeParser{token: stubToken{raw: "token"}}

	t.Run("WithTokenExtractor", func(t *testing.T) {
		customExtractor := func(r *http.Request) (string, error) {
			return r.URL.Query().Get("token"), nil
		}

		cfg, err := newMiddlewareConfig(mockParser, WithTokenExtractor(customExtractor))
		if err != nil {
			t.Fatalf("newMiddlewareConfig() error = %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/?token=query-token", nil)
		token, _ := cfg.extractor(req)
		if token != "query-token" {
			t.Errorf("Custom extractor not applied, got %q", token)
		}
	})

	t.Run("WithTokenExtractor nil", func(t *testing.T) {
		cfg, err := newMiddlewareConfig(mockParser, WithTokenExtractor(nil))
		if err != nil {
			t.Fatalf("newMiddlewareConfig() error = %v", err)
		}

		// Should use default extractor
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer test")
		token, _ := cfg.extractor(req)
		if token != "test" {
			t.Errorf("Should use default extractor when nil provided")
		}
	})

	t.Run("WithSkipper", func(t *testing.T) {
		customSkipper := func(r *http.Request) bool {
			return r.URL.Path == "/health"
		}

		cfg, err := newMiddlewareConfig(mockParser, WithSkipper(customSkipper))
		if err != nil {
			t.Fatalf("newMiddlewareConfig() error = %v", err)
		}

		healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
		if !cfg.skipper(healthReq) {
			t.Error("Skipper should return true for /health")
		}

		apiReq := httptest.NewRequest(http.MethodGet, "/api", nil)
		if cfg.skipper(apiReq) {
			t.Error("Skipper should return false for /api")
		}
	})

	t.Run("WithSkipper nil", func(t *testing.T) {
		cfg, err := newMiddlewareConfig(mockParser, WithSkipper(nil))
		if err != nil {
			t.Fatalf("newMiddlewareConfig() error = %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if cfg.skipper(req) {
			t.Error("Default skipper should return false")
		}
	})

	t.Run("WithErrorHandler", func(t *testing.T) {
		var handlerCalled bool
		customHandler := func(w http.ResponseWriter, r *http.Request, err error) {
			handlerCalled = true
			w.WriteHeader(http.StatusForbidden)
		}

		cfg, err := newMiddlewareConfig(mockParser, WithErrorHandler(customHandler))
		if err != nil {
			t.Fatalf("newMiddlewareConfig() error = %v", err)
		}

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		cfg.errorHandler(w, req, errors.New("test error"))

		if !handlerCalled {
			t.Error("Custom error handler not called")
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusForbidden)
		}
	})

	t.Run("WithErrorHandler nil", func(t *testing.T) {
		cfg, err := newMiddlewareConfig(mockParser, WithErrorHandler(nil))
		if err != nil {
			t.Fatalf("newMiddlewareConfig() error = %v", err)
		}

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		cfg.errorHandler(w, req, ErrTokenNotFound)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Default handler should return 401, got %d", w.Code)
		}
	})

	t.Run("multiple options", func(t *testing.T) {
		var skipperCalled, errorHandlerCalled bool

		cfg, err := newMiddlewareConfig(
			mockParser,
			WithSkipper(func(*http.Request) bool { skipperCalled = true; return false }),
			WithErrorHandler(func(http.ResponseWriter, *http.Request, error) { errorHandlerCalled = true }),
		)
		if err != nil {
			t.Fatalf("newMiddlewareConfig() error = %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		cfg.skipper(req)
		cfg.errorHandler(nil, req, nil)

		if !skipperCalled {
			t.Error("Skipper not applied")
		}
		if !errorHandlerCalled {
			t.Error("Error handler not applied")
		}
	})
}

func TestDefaultSkipper(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if defaultSkipper(req) {
		t.Error("defaultSkipper should always return false")
	}
}

func TestDefaultErrorHandler(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "generic error",
			err:        errors.New("something wrong"),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "token not found",
			err:        ErrTokenNotFound,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "context canceled",
			err:        context.Canceled,
			wantStatus: http.StatusGatewayTimeout,
		},
		{
			name:       "context deadline exceeded",
			err:        context.DeadlineExceeded,
			wantStatus: http.StatusGatewayTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			defaultErrorHandler(w, req, tt.err)

			if w.Code != tt.wantStatus {
				t.Errorf("defaultErrorHandler() status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestNewMiddlewareConfig(t *testing.T) {
	t.Run("nil parser", func(t *testing.T) {
		_, err := newMiddlewareConfig(nil)
		if err == nil {
			t.Error("newMiddlewareConfig() should return error for nil parser")
		}
	})

	t.Run("valid parser", func(t *testing.T) {
		parser := &fakeParser{token: stubToken{raw: "token"}}
		cfg, err := newMiddlewareConfig(parser)
		if err != nil {
			t.Errorf("newMiddlewareConfig() error = %v", err)
		}
		if cfg.parser != parser {
			t.Error("Parser not set correctly")
		}
		if cfg.extractor == nil {
			t.Error("Default extractor should be set")
		}
		if cfg.skipper == nil {
			t.Error("Default skipper should be set")
		}
		if cfg.errorHandler == nil {
			t.Error("Default error handler should be set")
		}
	})

	t.Run("nil option ignored", func(t *testing.T) {
		parser := &fakeParser{token: stubToken{raw: "token"}}
		_, err := newMiddlewareConfig(parser, nil, nil)
		if err != nil {
			t.Errorf("newMiddlewareConfig() should ignore nil options, got error = %v", err)
		}
	})
}
