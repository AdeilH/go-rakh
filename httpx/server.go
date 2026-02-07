package httpx

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

// Validator runs before route handlers; return an error to stop the pipeline.
type Validator func(Context) error

type Server struct {
	app      *App
	address  string
	srv      *http.Server
	shutdown time.Duration
}

type RouteRegistrar func(*App)

type StartOption func(*Server)

func WithShutdownTimeout(d time.Duration) StartOption {
	return func(s *Server) {
		if d > 0 {
			s.shutdown = d
		}
	}
}

func NewServer(opts ...ServerOption) *Server {
	cfg := defaultServerOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	a := New()
	a.e.HideBanner = true
	a.e.HidePort = true
	a.e.HTTPErrorHandler = wrapErrorHandler(cfg.ErrorHandler)
	a.e.Server.ReadTimeout = cfg.ReadTimeout
	a.e.Server.WriteTimeout = cfg.WriteTimeout
	for _, mw := range cfg.Middlewares {
		a.Use(mw)
	}
	if cfg.CORS != nil {
		a.Use(CORSMiddleware(cfg.CORS))
	}
	if len(cfg.Validators) > 0 {
		a.Use(validatorMiddleware(cfg.Validators...))
	}

	return &Server{
		app:      a,
		address:  cfg.Address,
		shutdown: 5 * time.Second,
	}
}

func (s *Server) RegisterRoutes(reg RouteRegistrar) {
	if reg != nil {
		reg(s.app)
	}
}

func (s *Server) Handler() http.Handler {
	return s.app.e
}

func (s *Server) Start(ctx context.Context, opts ...StartOption) error {
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	s.srv = &http.Server{
		Addr:         s.address,
		Handler:      s.app.e,
		ReadTimeout:  s.app.e.Server.ReadTimeout,
		WriteTimeout: s.app.e.Server.WriteTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdown)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// httpError is an internal error type
type httpError struct {
	Code    int
	Message interface{}
}

func (e *httpError) Error() string {
	if e.Message == nil {
		return http.StatusText(e.Code)
	}
	if str, ok := e.Message.(string); ok {
		return str
	}
	if err, ok := e.Message.(error); ok {
		return err.Error()
	}
	return http.StatusText(e.Code)
}

func wrapErrorHandler(h HTTPErrorHandler) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		h(err, c)
	}
}

func defaultHTTPErrorHandler(err error, c Context) {
	code := StatusInternalError
	msg := http.StatusText(code)
	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
		if str, ok := he.Message.(string); ok {
			msg = str
		} else if he.Message != nil {
			msg = he.Message.(error).Error()
		}
	} else if he, ok := err.(*httpError); ok {
		code = he.Code
		if str, ok := he.Message.(string); ok {
			msg = str
		} else if he.Message != nil {
			msg = he.Message.(error).Error()
		}
	}
	if !c.Response().Committed {
		_ = c.JSON(code, map[string]any{"error": msg})
	}
}

func validatorMiddleware(v ...Validator) MiddlewareFunc {
	copied := append([]Validator(nil), v...)
	return func(next HandlerFunc) HandlerFunc {
		return func(c Context) error {
			for _, validator := range copied {
				if validator == nil {
					continue
				}
				if err := validator(c); err != nil {
					return err
				}
			}
			return next(c)
		}
	}
}
