package auth

import (
	"context"
	"net/http"
)

type Middleware struct {
	parser       TokenParser
	extractor    TokenExtractor
	skipper      MiddlewareSkipper
	errorHandler MiddlewareErrorHandler
}

var tokenContextKey = struct{}{}

func NewMiddleware(parser TokenParser, opts ...MiddlewareOption) (*Middleware, error) {
	cfg, err := newMiddlewareConfig(parser, opts...)
	if err != nil {
		return nil, err
	}
	return &Middleware{
		parser:       cfg.parser,
		extractor:    cfg.extractor,
		skipper:      cfg.skipper,
		errorHandler: cfg.errorHandler,
	}, nil
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	if m == nil {
		panic("auth: middleware is nil")
	}
	if next == nil {
		next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.skipper(r) {
			next.ServeHTTP(w, r)
			return
		}

		raw, err := m.extractor(r)
		if err != nil {
			m.errorHandler(w, r, err)
			return
		}

		token, err := m.parser.ParseToken(r.Context(), raw)
		if err != nil {
			m.errorHandler(w, r, err)
			return
		}

		ctx := context.WithValue(r.Context(), tokenContextKey, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func TokenFromContext(ctx context.Context) (JWTToken, bool) {
	if ctx == nil {
		return nil, false
	}
	token, ok := ctx.Value(tokenContextKey).(JWTToken)
	return token, ok
}
