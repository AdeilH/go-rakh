package httpx

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// Context aliases echo.Context so callers can stay within httpx imports.
type Context = echo.Context

// HandlerFunc aliases echo.HandlerFunc.
type HandlerFunc = echo.HandlerFunc

// MiddlewareFunc aliases echo.MiddlewareFunc.
type MiddlewareFunc = echo.MiddlewareFunc

// Echo is a minimal wrapper exposing the underlying Echo instance when needed.
type Echo struct{ *echo.Echo }

// NewEcho creates a new Echo instance wrapped in httpx.Echo.
func NewEcho() *Echo { return &Echo{echo.New()} }

// Use attaches middleware to the Echo instance.
func (e *Echo) Use(mw ...MiddlewareFunc) { e.Echo.Use(mw...) }

// Group creates a route group with an optional prefix and middleware stack.
func (e *Echo) Group(prefix string, mw ...MiddlewareFunc) *echo.Group {
	return e.Echo.Group(prefix, mw...)
}

// RecoverMiddleware returns Echo's recover middleware.
func RecoverMiddleware() MiddlewareFunc { return middleware.Recover() }

// LoggerMiddleware returns Echo's logger middleware.
func LoggerMiddleware() MiddlewareFunc { return middleware.Logger() }

// CORSMiddleware builds a CORS middleware from the provided config; nil uses defaults.
func CORSMiddleware(cfg *middleware.CORSConfig) MiddlewareFunc {
	if cfg == nil {
		return middleware.CORSWithConfig(middleware.DefaultCORSConfig)
	}
	return middleware.CORSWithConfig(*cfg)
}

// GET registers a GET route.
func (e *Echo) GET(path string, h HandlerFunc, mw ...MiddlewareFunc) {
	e.Echo.GET(path, h, mw...)
}

// POST registers a POST route.
func (e *Echo) POST(path string, h HandlerFunc, mw ...MiddlewareFunc) {
	e.Echo.POST(path, h, mw...)
}

// PUT registers a PUT route.
func (e *Echo) PUT(path string, h HandlerFunc, mw ...MiddlewareFunc) {
	e.Echo.PUT(path, h, mw...)
}

// DELETE registers a DELETE route.
func (e *Echo) DELETE(path string, h HandlerFunc, mw ...MiddlewareFunc) {
	e.Echo.DELETE(path, h, mw...)
}

// HTTPError constructs an HTTPError without importing echo in callers.
func HTTPError(code int, message any) error { return echo.NewHTTPError(code, message) }

// DefaultCORSConfig mirrors echo's default CORS configuration.
var DefaultCORSConfig = middleware.DefaultCORSConfig
