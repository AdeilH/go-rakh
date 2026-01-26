package httpx

import (
	"strings"

	"github.com/labstack/echo/v4"
)

// Route represents a single HTTP route definition.
type Route struct {
	Method     string
	Path       string
	Handler    HandlerFunc
	Middleware []MiddlewareFunc
}

// RegisterRoutes applies a list of Route definitions to the Echo instance.
func RegisterRoutes(e *Echo, routes ...Route) {
	if e == nil || e.Echo == nil {
		return
	}
	for _, r := range routes {
		if r.Handler == nil || r.Path == "" || r.Method == "" {
			continue
		}
		e.Echo.Add(strings.ToUpper(r.Method), r.Path, r.Handler, r.Middleware...)
	}
}

// Router wraps an Echo group to provide chainable helpers for common verbs.
type Router struct {
	group *echo.Group
}

// NewRouter creates a router under an optional prefix with optional middleware.
func NewRouter(e *Echo, prefix string, mw ...MiddlewareFunc) *Router {
	if e == nil || e.Echo == nil {
		return &Router{}
	}
	return &Router{group: e.Group(prefix, mw...)}
}

func (r *Router) GET(path string, h HandlerFunc, mw ...MiddlewareFunc) *Router {
	r.add(echo.GET, path, h, mw...)
	return r
}

func (r *Router) POST(path string, h HandlerFunc, mw ...MiddlewareFunc) *Router {
	r.add(echo.POST, path, h, mw...)
	return r
}

func (r *Router) PUT(path string, h HandlerFunc, mw ...MiddlewareFunc) *Router {
	r.add(echo.PUT, path, h, mw...)
	return r
}

func (r *Router) DELETE(path string, h HandlerFunc, mw ...MiddlewareFunc) *Router {
	r.add(echo.DELETE, path, h, mw...)
	return r
}

func (r *Router) add(method, path string, h HandlerFunc, mw ...MiddlewareFunc) {
	if r.group == nil || h == nil || path == "" {
		return
	}
	r.group.Add(method, path, h, mw...)
}
