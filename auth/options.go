package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

var (
	ErrTokenNotFound     = errors.New("auth: token not found")
	ErrTokenInvalidInput = errors.New("auth: invalid token source")
)

type TokenParser interface {
	ParseToken(ctx context.Context, raw string) (JWTToken, error)
}

type TokenExtractor func(*http.Request) (string, error)

type MiddlewareSkipper func(*http.Request) bool

type MiddlewareErrorHandler func(http.ResponseWriter, *http.Request, error)

type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	parser       TokenParser
	extractor    TokenExtractor
	skipper      MiddlewareSkipper
	errorHandler MiddlewareErrorHandler
}

func newMiddlewareConfig(parser TokenParser, opts ...MiddlewareOption) (middlewareConfig, error) {
	if parser == nil {
		return middlewareConfig{}, errors.New("auth: middleware requires a token parser")
	}
	cfg := middlewareConfig{
		parser:       parser,
		extractor:    BearerTokenExtractor(),
		skipper:      defaultSkipper,
		errorHandler: defaultErrorHandler,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.extractor == nil {
		cfg.extractor = BearerTokenExtractor()
	}
	if cfg.skipper == nil {
		cfg.skipper = defaultSkipper
	}
	if cfg.errorHandler == nil {
		cfg.errorHandler = defaultErrorHandler
	}
	return cfg, nil
}

func WithTokenExtractor(extractor TokenExtractor) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		if extractor != nil {
			cfg.extractor = extractor
		}
	}
}

func WithSkipper(skipper MiddlewareSkipper) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		if skipper != nil {
			cfg.skipper = skipper
		}
	}
}

func WithErrorHandler(handler MiddlewareErrorHandler) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		if handler != nil {
			cfg.errorHandler = handler
		}
	}
}

func BearerTokenExtractor() TokenExtractor {
	return func(r *http.Request) (string, error) {
		header := r.Header.Get("Authorization")
		if header == "" {
			return "", ErrTokenNotFound
		}
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return "", ErrTokenInvalidInput
		}
		token := strings.TrimSpace(parts[1])
		if token == "" {
			return "", ErrTokenInvalidInput
		}
		return token, nil
	}
}

func CookieTokenExtractor(name string) TokenExtractor {
	name = strings.TrimSpace(name)
	return func(r *http.Request) (string, error) {
		if name == "" {
			return "", ErrTokenInvalidInput
		}
		cookie, err := r.Cookie(name)
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				return "", ErrTokenNotFound
			}
			return "", err
		}
		value := strings.TrimSpace(cookie.Value)
		if value == "" {
			return "", ErrTokenInvalidInput
		}
		return value, nil
	}
}

func ChainExtractors(extractors ...TokenExtractor) TokenExtractor {
	copied := append([]TokenExtractor(nil), extractors...)
	return func(r *http.Request) (string, error) {
		var lastErr error = ErrTokenNotFound
		for _, extractor := range copied {
			if extractor == nil {
				continue
			}
			token, err := extractor(r)
			if err == nil {
				return token, nil
			}
			lastErr = err
		}
		return "", lastErr
	}
}

func defaultSkipper(*http.Request) bool { return false }

func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	status := http.StatusUnauthorized
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		status = http.StatusGatewayTimeout
	}
	http.Error(w, err.Error(), status)
}
