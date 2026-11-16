package bifrostapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a small HTTP client for Bifrost. It sends the admin credentials as
// HTTP Basic authentication when a username is set.
type Client struct {
	BaseURL   string
	AdminUser string
	AdminPass string
	HTTP      *http.Client
}

// New returns a client for the Bifrost base URL.
func New(baseURL, adminUser, adminPass string) *Client {
	return &Client{
		BaseURL:   baseURL,
		AdminUser: adminUser,
		AdminPass: adminPass,
		HTTP:      &http.Client{Timeout: 60 * time.Second},
	}
}

// Response is an HTTP response with its body read.
type Response struct {
	Status int
	Body   []byte
}

// JSON decodes the body into a map. It returns an error if the body is not a
// JSON object.
func (r *Response) JSON() (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		return nil, fmt.Errorf("bifrostapi: decode body %q: %w", r.Body, err)
	}
	return m, nil
}

// Request describes one call.
type Request struct {
	Method  string
	Path    string
	Headers map[string]string
	// Body is encoded as JSON when it is not nil.
	Body any
	// NoAdmin stops the client from sending the admin credentials.
	NoAdmin bool
	// AdminUser and AdminPass replace the credentials of the client when
	// AdminUser is not empty.
	AdminUser string
	AdminPass string
}

// Do sends the request and reads the whole response body.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	var rd io.Reader
	if r.Body != nil {
		raw, err := json.Marshal(r.Body)
		if err != nil {
			return nil, fmt.Errorf("bifrostapi: encode body: %w", err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, c.BaseURL+r.Path, rd)
	if err != nil {
		return nil, fmt.Errorf("bifrostapi: new request: %w", err)
	}
	if r.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if !r.NoAdmin {
		user, pass := c.AdminUser, c.AdminPass
		if r.AdminUser != "" {
			user, pass = r.AdminUser, r.AdminPass
		}
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bifrostapi: %s %s: %w", r.Method, r.Path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("bifrostapi: read body: %w", err)
	}
	return &Response{Status: resp.StatusCode, Body: body}, nil
}
