// Package modelserver has a scripted OpenAI-compatible model server for the
// integration tests. It returns a fixed tool call when the request offers the
// scripted tool. Otherwise it returns a fixed text reply. It records the
// requests, so a test can examine the tools that Bifrost sent.
package modelserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Request is one request that the server got.
type Request struct {
	Path string
	// ToolNames are the names of the tools in the request body.
	ToolNames []string
	Body      []byte
}

// Server is a running scripted model server.
type Server struct {
	srv      *http.Server
	ln       net.Listener
	toolName string
	toolArgs string

	mu       sync.Mutex
	requests []Request
}

// Start starts the server on a free port of the loopback interface. The server
// returns a call of the tool toolName with the JSON arguments toolArgs when the
// request offers that tool.
func Start(toolName, toolArgs string) (*Server, error) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("modelserver: listen: %w", err)
	}
	s := &Server{ln: ln, toolName: toolName, toolArgs: toolArgs}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
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

// Mark returns the number of requests so far. Use it with Since.
func (s *Server) Mark() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// Since returns a copy of the requests after the mark.
func (s *Server) Since(mark int) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mark > len(s.requests) {
		mark = len(s.requests)
	}
	return append([]Request(nil), s.requests[mark:]...)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var parsed struct {
		Model string `json:"model"`
		Tools []struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(body, &parsed)
	rec := Request{Path: r.URL.Path, Body: body}
	offered := false
	for _, t := range parsed.Tools {
		rec.ToolNames = append(rec.ToolNames, t.Function.Name)
		if t.Function.Name == s.toolName {
			offered = true
		}
	}
	s.mu.Lock()
	s.requests = append(s.requests, rec)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/chat/completions":
		model := parsed.Model
		if model == "" {
			model = "scripted-model"
		}
		msg := map[string]any{"role": "assistant", "content": "scripted reply"}
		finish := "stop"
		if offered {
			msg = map[string]any{
				"role":    "assistant",
				"content": nil,
				"tool_calls": []any{map[string]any{
					"id":   "call_scripted_1",
					"type": "function",
					"function": map[string]any{
						"name":      s.toolName,
						"arguments": s.toolArgs,
					},
				}},
			}
			finish = "tool_calls"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-scripted",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   model,
			"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": finish}},
			"usage":   map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	case "/v1/models":
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []any{}})
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"not found"}}`))
	}
}
