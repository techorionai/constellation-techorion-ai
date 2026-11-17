// Package mcpserver has a real MCP server for the integration tests. It plays
// the application side: it records the method and the headers of each JSON-RPC
// request, and it rejects tools/call when the token is not one of the expected
// values. It answers the other methods, for example server/discover and
// tools/list, without a token.
package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolName is the name of the only tool of the server.
const ToolName = "echo"

// Record is one request that the server got.
type Record struct {
	// HTTPMethod is the HTTP method.
	HTTPMethod string
	// RPCMethod is the JSON-RPC method, for example tools/call. It is empty for
	// a request without a JSON-RPC body.
	RPCMethod string
	// Headers is a copy of the request headers.
	Headers http.Header
	// Rejected is true when the server answered 401.
	Rejected bool
}

// Authorization returns the Authorization header and whether it is present.
func (r Record) Authorization() (string, bool) {
	v := r.Headers.Values("Authorization")
	if len(v) == 0 {
		return "", false
	}
	return v[0], true
}

// Server is a running test MCP server.
type Server struct {
	srv *http.Server
	ln  net.Listener

	mu      sync.Mutex
	records []Record
	valid   map[string]bool
}

// Start starts the server on a free port of the loopback interface. Call Close
// to stop it.
func Start() (*Server, error) {
	s := &Server{valid: map[string]bool{}}
	mcpSrv := mcp.NewServer(&mcp.Implementation{Name: "helpdesk-test", Version: "0.0.1"}, nil)
	type echoIn struct {
		Message string `json:"message,omitempty" jsonschema:"text to echo"`
	}
	mcp.AddTool(mcpSrv, &mcp.Tool{Name: ToolName, Description: "Return the message."},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo: " + in.Message}}}, nil, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpSrv },
		&mcp.StreamableHTTPOptions{Stateless: true, DisableLocalhostProtection: true})

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("mcpserver: listen: %w", err)
	}
	s.ln = ln
	s.srv = &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serve(handler, w, r) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// Port returns the TCP port of the server.
func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Close stops the server.
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
}

// SetValidTokens sets the Authorization header values that tools/call accepts.
func (s *Server) SetValidTokens(values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.valid = map[string]bool{}
	for _, v := range values {
		s.valid[v] = true
	}
}

// Mark returns the number of records so far. Use it with Since.
func (s *Server) Mark() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// Since returns a copy of the records after the mark.
func (s *Server) Since(mark int) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mark > len(s.records) {
		mark = len(s.records)
	}
	return append([]Record(nil), s.records[mark:]...)
}

// All returns a copy of all records.
func (s *Server) All() []Record { return s.Since(0) }

func (s *Server) serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	methods := rpcMethods(body)
	rec := Record{HTTPMethod: r.Method, Headers: r.Header.Clone()}
	if len(methods) > 0 {
		rec.RPCMethod = methods[0]
	}
	reject := false
	for _, m := range methods {
		if m == "tools/call" {
			s.mu.Lock()
			ok := s.valid[r.Header.Get("Authorization")]
			s.mu.Unlock()
			if !ok {
				reject = true
			}
		}
	}
	rec.Rejected = reject
	s.mu.Lock()
	s.records = append(s.records, rec)
	s.mu.Unlock()
	if reject {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"helpdesk-test\"")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	next.ServeHTTP(w, r)
}

// rpcMethods returns the JSON-RPC methods in a single message or a batch.
func rpcMethods(body []byte) []string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil
	}
	type msg struct {
		Method string `json:"method"`
	}
	var out []string
	if body[0] == '[' {
		var batch []msg
		if json.Unmarshal(body, &batch) == nil {
			for _, m := range batch {
				out = append(out, m.Method)
			}
		}
		return out
	}
	var m msg
	if json.Unmarshal(body, &m) == nil && m.Method != "" {
		out = append(out, m.Method)
	}
	return out
}
