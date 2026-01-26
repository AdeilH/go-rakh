package httpx

import (
	"net/http"

	"github.com/adeilh/go-rakh/auth"
)

func AuthMiddleware(mw *auth.Middleware) MiddlewareFunc {
	if mw == nil {
		return func(next HandlerFunc) HandlerFunc {
			return func(c Context) error {
				return HTTPError(StatusUnauthorized, "auth middleware missing")
			}
		}
	}
	return func(next HandlerFunc) HandlerFunc {
		return func(c Context) error {
			downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				_ = next(c)
			})
			mw.Handler(downstream).ServeHTTP(c.Response(), c.Request())
			return nil
		}
	}
}
