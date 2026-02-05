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

// RegisterRoutes applies a list of Route definitions to the App instance.
func RegisterRoutes(a *App, routes ...Route) {
	if a == nil || a.e == nil {
		return
	}
	for _, r := range routes {
		if r.Handler == nil || r.Path == "" || r.Method == "" {
			continue
		}
		a.e.Add(strings.ToUpper(r.Method), r.Path, r.Handler, r.Middleware...)
	}
}

// group is an internal wrapper for route grouping
type group struct {
	g *echo.Group
}

func (a *App) newGroup(prefix string, mw ...MiddlewareFunc) *group {
	return &group{g: a.e.Group(prefix, mw...)}
}

// Router wraps an internal group to provide chainable helpers for common verbs.
type Router struct {
	group *group
}

// NewRouter creates a router under an optional prefix with optional middleware.
func NewRouter(a *App, prefix string, mw ...MiddlewareFunc) *Router {
	if a == nil || a.e == nil {
		return &Router{}
	}
	return &Router{group: a.newGroup(prefix, mw...)}
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
	if r.group == nil || r.group.g == nil || h == nil || path == "" {
		return
	}
	r.group.g.Add(method, path, h, mw...)
}
