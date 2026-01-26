package httpx

import (
	"net/http"
	"net/http/httptest"
)

// TestServer wraps httptest.Server so callers don't import net/http/httptest.
type TestServer struct{ *httptest.Server }

// NewTestServer starts a new TestServer from an http.Handler.
func NewTestServer(handler http.Handler) *TestServer {
	return &TestServer{httptest.NewServer(handler)}
}

// BaseURL returns the server's base URL.
func (ts *TestServer) BaseURL() string {
	if ts == nil || ts.Server == nil {
		return ""
	}
	return ts.URL
}

// NewEchoTestServer starts a TestServer from an httpx Echo instance.
func NewEchoTestServer(e *Echo) *TestServer {
	if e == nil {
		return nil
	}
	return &TestServer{httptest.NewServer(e.Echo)}
}
