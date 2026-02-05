package httpx

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// Context represents the context of the current HTTP request.
type Context = echo.Context

// HandlerFunc defines a function to handle HTTP requests.
type HandlerFunc = echo.HandlerFunc

// MiddlewareFunc defines a function to process middleware.
type MiddlewareFunc = echo.MiddlewareFunc

// App is the main application instance for handling HTTP requests.
type App struct{ e *echo.Echo }

// New creates a new App instance.
func New() *App { return &App{echo.New()} }

// Use attaches middleware to the App instance.
func (a *App) Use(mw ...MiddlewareFunc) { a.e.Use(mw...) }

// Group creates a route group with an optional prefix and middleware stack.
// Returns a Router that wraps the internal group.
func (a *App) Group(prefix string, mw ...MiddlewareFunc) *Router {
	return &Router{group: &group{g: a.e.Group(prefix, mw...)}}
}

// RecoverMiddleware returns a middleware that recovers from panics.
func RecoverMiddleware() MiddlewareFunc { return middleware.Recover() }

// LoggerMiddleware returns a middleware that logs HTTP requests.
func LoggerMiddleware() MiddlewareFunc { return middleware.Logger() }

// CORSMiddleware builds a CORS middleware from the provided config; nil uses defaults.
func CORSMiddleware(cfg *middleware.CORSConfig) MiddlewareFunc {
	if cfg == nil {
		return middleware.CORSWithConfig(middleware.DefaultCORSConfig)
	}
	return middleware.CORSWithConfig(*cfg)
}

// GET registers a GET route.
func (a *App) GET(path string, h HandlerFunc, mw ...MiddlewareFunc) {
	a.e.GET(path, h, mw...)
}

// POST registers a POST route.
func (a *App) POST(path string, h HandlerFunc, mw ...MiddlewareFunc) {
	a.e.POST(path, h, mw...)
}

// PUT registers a PUT route.
func (a *App) PUT(path string, h HandlerFunc, mw ...MiddlewareFunc) {
	a.e.PUT(path, h, mw...)
}

// DELETE registers a DELETE route.
func (a *App) DELETE(path string, h HandlerFunc, mw ...MiddlewareFunc) {
	a.e.DELETE(path, h, mw...)
}

// PATCH registers a PATCH route.
func (a *App) PATCH(path string, h HandlerFunc, mw ...MiddlewareFunc) {
	a.e.PATCH(path, h, mw...)
}

// HTTPError constructs an HTTP error for returning from handlers.
func HTTPError(code int, message any) error { return &httpError{Code: code, Message: message} }

// DefaultCORSConfig provides the default CORS configuration.
var DefaultCORSConfig = middleware.DefaultCORSConfig
