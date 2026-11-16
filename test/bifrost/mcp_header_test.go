//go:build integration

package bifrost

import (
	"encoding/json"
	"strings"
	"testing"
)

// I4: add the test MCP server and list the clients. Bifrost sends its
// discovery requests without the Authorization header (D5). Observed: Bifrost
// v2.5.1 speaks the MCP protocol version 2026-07-28. It sends server/discover
// and tools/list, and it does not send initialize (D15).
func (s *suite) i4AddMCPClient(t *testing.T) {
	mark := s.mcp.Mark()
	r := s.admin(t, "POST", "/api/mcp/client", s.clientBody())
	t.Logf("POST /api/mcp/client: %d %s", r.Status, r.Body)
	if r.Status != 200 {
		t.Fatalf("add MCP client: %d %s", r.Status, r.Body)
	}

	list := s.admin(t, "GET", "/api/mcp/clients", nil)
	if list.Status != 200 {
		t.Fatalf("GET /api/mcp/clients: %d %s", list.Status, list.Body)
	}
	var out struct {
		Clients []struct {
			Config struct {
				ClientID string `json:"client_id"`
				Name     string `json:"name"`
			} `json:"config"`
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"clients"`
	}
	s.must(t, json.Unmarshal(list.Body, &out))
	found := false
	for _, c := range out.Clients {
		if c.Config.Name != clientName {
			continue
		}
		found = true
		var names []string
		hasTool := false
		for _, tl := range c.Tools {
			names = append(names, tl.Name)
			if strings.HasSuffix(tl.Name, "echo") {
				hasTool = true
			}
		}
		t.Logf("tools of the client: %v", names)
		if !hasTool {
			t.Errorf("the client has no echo tool: %v", names)
		}
	}
	if !found {
		t.Fatalf("the list has no client %s: %s", clientName, list.Body)
	}

	recs := s.mcp.Since(mark)
	t.Logf("MCP methods at add time: %v", rpcMethods(recs))
	var sawDiscover, sawList bool
	for _, rec := range recs {
		if _, ok := rec.Authorization(); ok {
			t.Errorf("%s at add time has the Authorization header", rec.RPCMethod)
		}
		switch rec.RPCMethod {
		case "server/discover":
			sawDiscover = true
		case "tools/list":
			sawList = true
		case "initialize":
			t.Errorf("Bifrost sent initialize at add time. Update the observed behavior in docs/bifrost.md.")
		}
	}
	if !sawDiscover || !sawList {
		t.Errorf("the test MCP server did not get server/discover and tools/list (server/discover %v, tools/list %v)", sawDiscover, sawList)
	}
}

// I5: a tool call with a per-call token. The token gets to tools/call, and to
// the server/discover request of the same call (observed, D15). Bifrost sends no
// initialize.
func (s *suite) i5PerCallAuthorization(t *testing.T) {
	s.vkAll = s.createVirtualKey(t, "spike_all_tools", []string{"*"})
	mark := s.mcp.Mark()
	r := s.executeTool(t, map[string]string{
		"x-bf-vk":       s.vkAll,
		"Authorization": "Bearer " + s.secrets.TokenA,
	})
	t.Logf("tool execute: %d %s", r.Status, r.Body)
	if r.Status != 200 {
		t.Fatalf("tool execute: %d %s", r.Status, r.Body)
	}
	var msg struct {
		Role string `json:"role"`
	}
	s.must(t, json.Unmarshal(r.Body, &msg))
	if msg.Role != "tool" {
		t.Errorf("the response role is %q, want tool", msg.Role)
	}
	recs := s.mcp.Since(mark)
	t.Logf("MCP methods during the call: %v", rpcMethods(recs))
	want := "Bearer " + s.secrets.TokenA
	calls := toolsCalls(recs)
	if len(calls) != 1 {
		t.Fatalf("tools/call count %d, want 1", len(calls))
	}
	if got, _ := calls[0].Authorization(); got != want {
		t.Errorf("tools/call Authorization does not match token A")
	}
	var discovers int
	for _, rec := range recs {
		switch rec.RPCMethod {
		case "server/discover":
			discovers++
			if got, _ := rec.Authorization(); got != want {
				t.Errorf("server/discover of the call: the Authorization header does not match token A")
			}
		case "initialize":
			t.Errorf("Bifrost sent initialize during the call. Update the observed behavior in docs/bifrost.md.")
		}
	}
	if discovers == 0 {
		t.Errorf("no server/discover during the call: Bifrost did not open a new connection")
	}
}

// I6: a second call with token B. The server gets token B and does not get
// token A again.
func (s *suite) i6SecondToken(t *testing.T) {
	mark := s.mcp.Mark()
	r := s.executeTool(t, map[string]string{
		"x-bf-vk":       s.vkAll,
		"Authorization": "Bearer " + s.secrets.TokenB,
	})
	if r.Status != 200 {
		t.Fatalf("tool execute: %d %s", r.Status, r.Body)
	}
	recs := s.mcp.Since(mark)
	calls := toolsCalls(recs)
	if len(calls) != 1 {
		t.Fatalf("tools/call count %d, want 1", len(calls))
	}
	if got, _ := calls[0].Authorization(); got != "Bearer "+s.secrets.TokenB {
		t.Errorf("tools/call Authorization does not match token B")
	}
	if strings.Contains(headerDump(recs), s.secrets.TokenA) {
		t.Errorf("token A is in a request of the second call")
	}
}

// I7: a token that the MCP server rejects with 401.
func (s *suite) i7RejectedToken(t *testing.T) {
	mark := s.mcp.Mark()
	r := s.executeTool(t, map[string]string{
		"x-bf-vk":       s.vkAll,
		"Authorization": "Bearer " + s.secrets.TokenBad,
	})
	msg := s.stack.Redact(errorMessage(r.Body))
	t.Logf("RESULT I7 status=%d message=%q", r.Status, msg)
	if r.Status != 400 {
		t.Errorf("status %d, want 400", r.Status)
	}
	if msg == "" {
		t.Errorf("the error response has no message")
	}
	calls := toolsCalls(s.mcp.Since(mark))
	if len(calls) != 1 || !calls[0].Rejected {
		t.Errorf("the test MCP server did not get and reject one tools/call: %d calls", len(calls))
	}
}

// I8: a tool call with the virtual key and without the Authorization header.
func (s *suite) i8NoAuthorization(t *testing.T) {
	mark := s.mcp.Mark()
	r := s.executeTool(t, map[string]string{"x-bf-vk": s.vkAll})
	t.Logf("RESULT I8 status=%d message=%q", r.Status, s.stack.Redact(errorMessage(r.Body)))
	recs := s.mcp.Since(mark)
	calls := toolsCalls(recs)
	if len(calls) == 0 {
		t.Fatalf("the test MCP server got no tools/call")
	}
	for _, c := range calls {
		if _, ok := c.Authorization(); ok {
			t.Errorf("tools/call has an Authorization header")
		}
	}
	if strings.Contains(headerDump(recs), s.vkAll) {
		t.Errorf("the virtual key value is in a header that the test MCP server got")
	}
}

// I9: a tool call with Authorization and without the virtual key.
func (s *suite) i9NoVirtualKey(t *testing.T) {
	mark := s.mcp.Mark()
	r := s.executeTool(t, map[string]string{"Authorization": "Bearer " + s.secrets.TokenA})
	if r.Status != 401 {
		t.Errorf("status %d %s, want 401", r.Status, s.stack.Redact(string(r.Body)))
	}
	if n := len(toolsCalls(s.mcp.Since(mark))); n != 0 {
		t.Errorf("the test MCP server got %d tools/call, want 0", n)
	}
}
