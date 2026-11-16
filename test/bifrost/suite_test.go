//go:build integration

// Package bifrost has the integration tests of the Bifrost spike. They run the
// upstream Bifrost image with PostgreSQL, a network capture, a test MCP server,
// and a scripted model server.
package bifrost

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/techorionai/constellation-techorion-ai/resources/test/bifrostapi"
	"github.com/techorionai/constellation-techorion-ai/resources/test/containers"
	"github.com/techorionai/constellation-techorion-ai/resources/test/mcpserver"
	"github.com/techorionai/constellation-techorion-ai/resources/test/modelserver"
)

// captureWait is the time that the capture runs after the last call (D12).
// Bifrost background jobs run every 5 minutes. The environment variable
// SPIKE_CAPTURE_WAIT_SECONDS is for a faster local run while you develop. Do
// not use it for a real result.
func captureWait(t *testing.T) time.Duration {
	if v := os.Getenv("SPIKE_CAPTURE_WAIT_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			t.Fatalf("SPIKE_CAPTURE_WAIT_SECONDS=%q is not a number of seconds", v)
		}
		t.Logf("WARNING: the capture wait is %d seconds, not 6 minutes (SPIKE_CAPTURE_WAIT_SECONDS)", n)
		return time.Duration(n) * time.Second
	}
	return 6 * time.Minute
}

// clientName is the name of the MCP client. A client name has no hyphen.
const clientName = "helpdesk_test"

// clientID is the fixed ID of the MCP client.
const clientID = "helpdesk-test-client"

// toolName is the tool name that a caller sees: <client name>-<tool name>.
const toolName = clientName + "-" + mcpserver.ToolName

// suite is the shared state of the tests that use one Bifrost container set.
type suite struct {
	secrets bifrostapi.Secrets
	stack   *containers.Stack
	api     *bifrostapi.Client
	mcp     *mcpserver.Server
	model   *modelserver.Server

	vkAll  string // value of virtual key 1 (all tools)
	vkNone string // value of virtual key 2 (no tools)
}

// TestBifrost runs the tests I1 to I14, I16, I17, and I18 in the order that
// the plan gives. They share one Bifrost container set. The capture runs from
// before Bifrost starts to the end of I14.
func TestBifrost(t *testing.T) {
	secrets, err := bifrostapi.NewSecrets()
	if err != nil {
		t.Fatal(err)
	}
	mcp, err := mcpserver.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer mcp.Close()
	mcp.SetValidTokens("Bearer "+secrets.TokenA, "Bearer "+secrets.TokenB)
	model, err := modelserver.Start(toolName, `{"message":"hello"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer model.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	stack, err := containers.Start(ctx, containers.Options{
		Secrets:   secrets,
		HostPorts: []int{mcp.Port(), model.Port()},
		ModelPort: model.Port(),
	})
	if err != nil {
		t.Fatalf("start the container set: %v", stack.Redact(err.Error()))
	}
	defer stack.Close()

	s := &suite{
		secrets: secrets,
		stack:   stack,
		api:     bifrostapi.New(stack.BaseURL, secrets.AdminUser, secrets.AdminPassword),
		mcp:     mcp,
		model:   model,
	}
	steps := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"I1_Startup", s.i1Startup},
		{"I2_NewsFeedSwitch", s.i2NewsFeedSwitch},
		{"I3_ManagementWithoutCredentials", s.i3NoCredentials},
		{"I18_ManagementWrongPassword", s.i18WrongPassword},
		{"I4_AddMCPClient", s.i4AddMCPClient},
		{"I5_PerCallAuthorization", s.i5PerCallAuthorization},
		{"I6_SecondToken", s.i6SecondToken},
		{"I7_RejectedToken", s.i7RejectedToken},
		{"I8_NoAuthorizationHeader", s.i8NoAuthorization},
		{"I9_NoVirtualKey", s.i9NoVirtualKey},
		{"I10_DefaultToolMode", s.i10DefaultToolMode},
		{"I11_IncludeToolsFilter", s.i11IncludeTools},
		{"I16_KeyWithoutTools", s.i16KeyWithoutTools},
		{"I17_UnknownVirtualKey", s.i17UnknownVirtualKey},
		{"I12_ManagementBehavior", s.i12ManagementBehavior},
		{"I13_NoTokenInLogsOrDatabase", s.i13NoTokenStored},
		{"I14_NoUnexpectedEgress", s.i14Egress},
	}
	for _, st := range steps {
		if !t.Run(st.name, st.fn) {
			t.Logf("%s failed. The next tests can fail because of it.", st.name)
		}
	}
}

// must fails the test now when err is not nil. It removes secret values from
// the message.
func (s *suite) must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(s.stack.Redact(err.Error()))
	}
}

// admin sends a call with the admin credentials.
func (s *suite) admin(t *testing.T, method, path string, body any) *bifrostapi.Response {
	t.Helper()
	r, err := s.api.Do(context.Background(), bifrostapi.Request{Method: method, Path: path, Body: body})
	s.must(t, err)
	return r
}

// call sends a call with the given headers and without admin credentials.
func (s *suite) call(t *testing.T, method, path string, headers map[string]string, body any) *bifrostapi.Response {
	t.Helper()
	r, err := s.api.Do(context.Background(), bifrostapi.Request{
		Method: method, Path: path, Headers: headers, Body: body, NoAdmin: true,
	})
	s.must(t, err)
	return r
}
