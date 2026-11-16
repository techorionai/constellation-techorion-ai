//go:build integration

package bifrost

import (
	"encoding/json"
	"slices"
	"testing"
)

// chatResult is the part of a chat completion that the tests read.
type chatResult struct {
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			ToolCalls []struct {
				ID       string `json:"id"`
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

// I10: the default tool mode. The tool call goes back to the caller and Bifrost
// does not run it.
func (s *suite) i10DefaultToolMode(t *testing.T) {
	mcpMark := s.mcp.Mark()
	modelMark := s.model.Mark()
	r := s.chat(t, map[string]string{"x-bf-vk": s.vkAll})
	t.Logf("chat: %d %s", r.Status, s.stack.Redact(string(r.Body)))
	if r.Status != 200 {
		t.Fatalf("chat: %d %s", r.Status, s.stack.Redact(string(r.Body)))
	}
	var res chatResult
	s.must(t, json.Unmarshal(r.Body, &res))
	if len(res.Choices) == 0 {
		t.Fatalf("the response has no choice")
	}
	c := res.Choices[0]
	if c.FinishReason != "tool_calls" {
		t.Errorf("finish_reason %q, want tool_calls", c.FinishReason)
	}
	if len(c.Message.ToolCalls) != 1 || c.Message.ToolCalls[0].Function.Name != toolName {
		t.Errorf("tool calls %+v, want one call of %s", c.Message.ToolCalls, toolName)
	}
	if n := len(toolsCalls(s.mcp.Since(mcpMark))); n != 0 {
		t.Errorf("the test MCP server got %d tools/call, want 0", n)
	}
	reqs := s.model.Since(modelMark)
	if len(reqs) == 0 {
		t.Fatalf("the model server got no request")
	}
	if !slices.Contains(reqs[0].ToolNames, toolName) {
		t.Errorf("the model request has the tools %v, want %s", reqs[0].ToolNames, toolName)
	}
}

// I11: the header x-bf-mcp-include-tools with a tool name that does not exist.
func (s *suite) i11IncludeTools(t *testing.T) {
	modelMark := s.model.Mark()
	r := s.chat(t, map[string]string{
		"x-bf-vk":                s.vkAll,
		"x-bf-mcp-include-tools": clientName + "-does_not_exist",
	})
	t.Logf("chat: %d %s", r.Status, s.stack.Redact(string(r.Body)))
	if r.Status != 200 {
		t.Fatalf("chat: %d %s", r.Status, s.stack.Redact(string(r.Body)))
	}
	reqs := s.model.Since(modelMark)
	if len(reqs) == 0 {
		t.Fatalf("the model server got no request")
	}
	if len(reqs[0].ToolNames) != 0 {
		t.Errorf("the model request has the tools %v, want none", reqs[0].ToolNames)
	}
}

// I16: a virtual key with an empty tools_to_execute. The model gets no MCP
// tools, and the tool call fails.
func (s *suite) i16KeyWithoutTools(t *testing.T) {
	s.vkNone = s.createVirtualKey(t, "spike_no_tools", []string{})
	modelMark := s.model.Mark()
	r := s.chat(t, map[string]string{"x-bf-vk": s.vkNone})
	t.Logf("chat: %d %s", r.Status, s.stack.Redact(string(r.Body)))
	if r.Status != 200 {
		t.Fatalf("chat: %d %s", r.Status, s.stack.Redact(string(r.Body)))
	}
	reqs := s.model.Since(modelMark)
	if len(reqs) == 0 {
		t.Fatalf("the model server got no request")
	}
	if len(reqs[0].ToolNames) != 0 {
		t.Errorf("the model request has the tools %v, want none", reqs[0].ToolNames)
	}

	mcpMark := s.mcp.Mark()
	x := s.executeTool(t, map[string]string{
		"x-bf-vk":       s.vkNone,
		"Authorization": "Bearer " + s.secrets.TokenA,
	})
	msg := s.stack.Redact(errorMessage(x.Body))
	t.Logf("RESULT I16 status=%d message=%q", x.Status, msg)
	if x.Status < 400 {
		t.Errorf("the tool call returned %d, want an error status", x.Status)
	}
	if n := len(toolsCalls(s.mcp.Since(mcpMark))); n != 0 {
		t.Errorf("the test MCP server got %d tools/call, want 0", n)
	}
}

// I17: a virtual key value that does not exist.
func (s *suite) i17UnknownVirtualKey(t *testing.T) {
	mark := s.mcp.Mark()
	r := s.executeTool(t, map[string]string{
		"x-bf-vk":       "sk-bf-" + s.secrets.TokenBad,
		"Authorization": "Bearer " + s.secrets.TokenA,
	})
	if r.Status != 401 {
		t.Errorf("status %d %s, want 401", r.Status, s.stack.Redact(string(r.Body)))
	}
	if n := len(toolsCalls(s.mcp.Since(mark))); n != 0 {
		t.Errorf("the test MCP server got %d tools/call, want 0", n)
	}
}
