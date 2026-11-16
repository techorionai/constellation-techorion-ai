//go:build integration

package bifrost

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/techorionai/constellation-techorion-ai/resources/test/bifrostapi"
	"github.com/techorionai/constellation-techorion-ai/resources/test/containers"
	"github.com/techorionai/constellation-techorion-ai/resources/test/mcpserver"
)

// mcpURL is the URL of the test MCP server as Bifrost sees it.
func (s *suite) mcpURL() string {
	return fmt.Sprintf("http://%s:%d/mcp", containers.HostInternal, s.mcp.Port())
}

// clientBody is the MCP client body of the Design section of the plan.
func (s *suite) clientBody() map[string]any {
	return map[string]any{
		"client_id":             clientID,
		"name":                  clientName,
		"connection_type":       "http",
		"connection_string":     s.mcpURL(),
		"auth_type":             "none",
		"allowed_extra_headers": []string{"authorization"},
		"tools_to_execute":      []string{"*"},
		"allow_by_default":      true,
	}
}

// providerKeyID returns the ID of the key of the OpenAI provider. A virtual key
// gets no provider key unless the body lists its ID in key_ids.
func (s *suite) providerKeyID(t *testing.T) string {
	t.Helper()
	r := s.admin(t, "GET", "/api/providers/openai/keys", nil)
	if r.Status != 200 {
		t.Fatalf("GET /api/providers/openai/keys: %d %s", r.Status, s.stack.Redact(string(r.Body)))
	}
	var out struct {
		Keys []struct {
			ID string `json:"id"`
		} `json:"keys"`
	}
	s.must(t, json.Unmarshal(r.Body, &out))
	if len(out.Keys) != 1 || out.Keys[0].ID == "" {
		t.Fatalf("the OpenAI provider has %d keys, want 1", len(out.Keys))
	}
	return out.Keys[0].ID
}

// createVirtualKey makes a virtual key through the management API and returns
// its value. The value does not go to the test log.
func (s *suite) createVirtualKey(t *testing.T, name string, toolsToExecute []string) string {
	t.Helper()
	body := map[string]any{
		"name": name,
		"provider_configs": []any{map[string]any{
			"provider":       "openai",
			"allowed_models": []string{"*"},
			"key_ids":        []string{s.providerKeyID(t)},
		}},
		"mcp_configs": []any{map[string]any{
			"mcp_client_name":  clientName,
			"tools_to_execute": toolsToExecute,
		}},
	}
	r := s.admin(t, "POST", "/api/governance/virtual-keys", body)
	if r.Status != 200 && r.Status != 201 {
		t.Fatalf("create virtual key %s: %d %s", name, r.Status, s.stack.Redact(string(r.Body)))
	}
	var out struct {
		VirtualKey struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"virtual_key"`
	}
	if err := json.Unmarshal(r.Body, &out); err != nil || out.VirtualKey.Value == "" {
		t.Fatalf("create virtual key %s: the response has no virtual_key.value (status %d)", name, r.Status)
	}
	return out.VirtualKey.Value
}

// executeTool sends POST /v1/mcp/tool/execute for the test tool.
func (s *suite) executeTool(t *testing.T, headers map[string]string) *bifrostapi.Response {
	t.Helper()
	body := map[string]any{
		"id":   "call_test_1",
		"type": "function",
		"function": map[string]any{
			"name":      toolName,
			"arguments": `{"message":"hello"}`,
		},
	}
	return s.call(t, "POST", "/v1/mcp/tool/execute", headers, body)
}

// chat sends POST /v1/chat/completions.
func (s *suite) chat(t *testing.T, headers map[string]string) *bifrostapi.Response {
	t.Helper()
	body := map[string]any{
		"model":    "openai/gpt-4o",
		"messages": []any{map[string]any{"role": "user", "content": "Say hello with the tool."}},
	}
	return s.call(t, "POST", "/v1/chat/completions", headers, body)
}

// toolCalls returns the RPC methods of the records.
func rpcMethods(recs []mcpserver.Record) []string {
	var out []string
	for _, r := range recs {
		out = append(out, r.RPCMethod)
	}
	return out
}

// toolsCalls returns the records of tools/call.
func toolsCalls(recs []mcpserver.Record) []mcpserver.Record {
	var out []mcpserver.Record
	for _, r := range recs {
		if r.RPCMethod == "tools/call" {
			out = append(out, r)
		}
	}
	return out
}

// headerDump returns all header names and values of the records as one text.
func headerDump(recs []mcpserver.Record) string {
	var b strings.Builder
	for _, r := range recs {
		for k, vs := range r.Headers {
			for _, v := range vs {
				b.WriteString(k + ": " + v + "\n")
			}
		}
	}
	return b.String()
}

// errorMessage returns the error message of a Bifrost error body, or the whole
// body when it has no message.
func errorMessage(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil {
		if e.Error.Message != "" {
			return e.Error.Message
		}
		if e.Message != "" {
			return e.Message
		}
	}
	return string(body)
}
