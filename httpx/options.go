package httpx

import (
	"time"

	"github.com/labstack/echo/v4/middleware"
)

// HTTPErrorHandler is a function that handles errors during request processing.
type HTTPErrorHandler func(error, Context)

type ServerOptions struct {
	Address      string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	Middlewares  []MiddlewareFunc
	ErrorHandler HTTPErrorHandler
	Validators   []Validator
	CORS         *middleware.CORSConfig
}

type ServerOption func(*ServerOptions)

func defaultServerOptions() ServerOptions {
	return ServerOptions{
		Address:      ":8080",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		Middlewares:  []MiddlewareFunc{RecoverMiddleware(), LoggerMiddleware()},
		ErrorHandler: defaultHTTPErrorHandler,
	}
}

func WithAddress(addr string) ServerOption {
	return func(o *ServerOptions) {
		if addr != "" {
			o.Address = addr
		}
	}
}

func WithTimeouts(read, write time.Duration) ServerOption {
	return func(o *ServerOptions) {
		if read > 0 {
			o.ReadTimeout = read
		}
		if write > 0 {
			o.WriteTimeout = write
		}
	}
}

func WithMiddlewares(mw ...MiddlewareFunc) ServerOption {
	return func(o *ServerOptions) {
		if len(mw) > 0 {
			o.Middlewares = append([]MiddlewareFunc{}, mw...)
		}
	}
}

// AppendMiddlewares appends additional middleware to the existing stack.
func AppendMiddlewares(mw ...MiddlewareFunc) ServerOption {
	return func(o *ServerOptions) {
		if len(mw) > 0 {
			o.Middlewares = append(o.Middlewares, mw...)
		}
	}
}

func WithErrorHandler(handler HTTPErrorHandler) ServerOption {
	return func(o *ServerOptions) {
		if handler != nil {
			o.ErrorHandler = handler
		}
	}
}

// WithValidators installs request-level validators executed before route handlers.
func WithValidators(v ...Validator) ServerOption {
	return func(o *ServerOptions) {
		if len(v) > 0 {
			o.Validators = append([]Validator{}, v...)
		}
	}
}

// WithCORS enables CORS middleware using the provided configuration; if cfg is nil, the default config is used.
func WithCORS(cfg *middleware.CORSConfig) ServerOption {
	return func(o *ServerOptions) {
		if cfg == nil {
			def := middleware.DefaultCORSConfig
			o.CORS = &def
			return
		}
		o.CORS = cfg
	}
}

type ClientOptions struct {
	BaseURL     string
	Timeout     time.Duration
	Headers     map[string]string
	RestyConfig func(RestClient)
}

type ClientOption func(*ClientOptions)

func defaultClientOptions() ClientOptions {
	return ClientOptions{Timeout: 10 * time.Second, Headers: map[string]string{"Content-Type": "application/json"}}
}

func WithBaseURL(url string) ClientOption {
	return func(o *ClientOptions) {
		if url != "" {
			o.BaseURL = url
		}
	}
}

func WithClientTimeout(d time.Duration) ClientOption {
	return func(o *ClientOptions) {
		if d > 0 {
			o.Timeout = d
		}
	}
}

func WithHeaders(headers map[string]string) ClientOption {
	return func(o *ClientOptions) {
		if len(headers) == 0 {
			return
		}
		o.Headers = make(map[string]string, len(headers))
		for k, v := range headers {
			o.Headers[k] = v
		}
	}
}

func WithRestyConfig(fn func(RestClient)) ClientOption {
	return func(o *ClientOptions) {
		o.RestyConfig = fn
	}
}
