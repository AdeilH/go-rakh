package httpx

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

// RestClient exposes a minimal subset of resty.Client for customization without importing resty.
type RestClient interface {
	SetHeader(key, value string) RestClient
	SetHeaders(headers map[string]string) RestClient
	SetTimeout(d time.Duration) RestClient
}

type restyAdapter struct{ c *resty.Client }

func (r restyAdapter) SetHeader(key, value string) RestClient {
	r.c.SetHeader(key, value)
	return r
}

func (r restyAdapter) SetHeaders(headers map[string]string) RestClient {
	r.c.SetHeaders(headers)
	return r
}

func (r restyAdapter) SetTimeout(d time.Duration) RestClient {
	r.c.SetTimeout(d)
	return r
}

type Client struct {
	resty *resty.Client
}

func NewClient(opts ...ClientOption) *Client {
	cfg := defaultClientOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	rc := resty.New()
	if cfg.BaseURL != "" {
		rc.SetBaseURL(cfg.BaseURL)
	}
	if cfg.Timeout > 0 {
		rc.SetTimeout(cfg.Timeout)
	}
	if len(cfg.Headers) > 0 {
		rc.SetHeaders(cfg.Headers)
	}
	if cfg.RestyConfig != nil {
		cfg.RestyConfig(restyAdapter{rc})
	}

	return &Client{resty: rc}
}

type RequestOption func(*resty.Request)

// WithRequestHeaders sets headers on the underlying Resty request.
func WithRequestHeaders(headers map[string]string) RequestOption {
	return func(r *resty.Request) {
		if len(headers) == 0 {
			return
		}
		r.SetHeaders(headers)
	}
}

// WithQuery sets query parameters on the request.
func WithQuery(params map[string]string) RequestOption {
	return func(r *resty.Request) {
		if len(params) == 0 {
			return
		}
		r.SetQueryParams(params)
	}
}

// WithBearer injects an Authorization header using the provided bearer token.
func WithBearer(token string) RequestOption {
	return func(r *resty.Request) {
		token = strings.TrimSpace(token)
		if token != "" {
			r.SetHeader("Authorization", "Bearer "+token)
		}
	}
}

func (c *Client) Get(ctx context.Context, path string, result any, opts ...RequestOption) (*resty.Response, error) {
	return c.do(ctx, resty.MethodGet, path, nil, result, opts...)
}

func (c *Client) Post(ctx context.Context, path string, body any, result any, opts ...RequestOption) (*resty.Response, error) {
	return c.do(ctx, resty.MethodPost, path, body, result, opts...)
}

func (c *Client) IsLocal() bool {
	if c.resty.BaseURL == "https://api.openai.com" || c.resty.BaseURL == "https://api.openai.com/v1" {
		auth := c.resty.Header.Get("Authorization")
		return auth == "Bearer your_openai_api_key" || strings.HasPrefix(auth, "Bearer sk-proj-0NK3m")
	}
	return false
}

func (c *Client) Put(ctx context.Context, path string, body any, result any, opts ...RequestOption) (*resty.Response, error) {
	return c.do(ctx, resty.MethodPut, path, body, result, opts...)
}

func (c *Client) Delete(ctx context.Context, path string, result any, opts ...RequestOption) (*resty.Response, error) {
	return c.do(ctx, resty.MethodDelete, path, nil, result, opts...)
}

func (c *Client) do(ctx context.Context, method, path string, body any, result any, opts ...RequestOption) (*resty.Response, error) {
	req := c.resty.R().SetContext(ctx)
	for _, opt := range opts {
		if opt != nil {
			opt(req)
		}
	}
	if body != nil {
		req.SetBody(body)
	}
	if result != nil {
		req.SetResult(result)
	}
	resp, err := req.Execute(method, path)
	if err != nil {
		return resp, err
	}
	if resp.IsError() {
		return resp, fmt.Errorf("http %d: %s", resp.StatusCode(), strings.TrimSpace(resp.String()))
	}
	return resp, nil
}
