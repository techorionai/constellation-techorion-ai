//go:build integration

// Package bifrost has the integration tests of the Bifrost spike. They run the
// upstream Bifrost image with PostgreSQL, a network capture, a test MCP server,
// and a scripted model server.
package bifrost

import (
	"context"
	"fmt"
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
// not use it for a real result. The test fails when it is set and the
// environment variable CI is set, so a CI run always has the full wait.
func captureWait(t *testing.T) time.Duration {
	t.Helper()
	d, warn, err := captureWaitFrom(os.Getenv("CI"), os.Getenv("SPIKE_CAPTURE_WAIT_SECONDS"))
	if err != nil {
		t.Fatal(err)
	}
	if warn != "" {
		t.Log(warn)
	}
	return d
}

// fullCaptureWait is the wait of the I14 test without SPIKE_CAPTURE_WAIT_SECONDS.
const fullCaptureWait = 6 * time.Minute

// captureWaitFrom returns the capture wait for the values of the environment
// variables CI and SPIKE_CAPTURE_WAIT_SECONDS.
func captureWaitFrom(ci, v string) (d time.Duration, warning string, err error) {
	if v == "" {
		return fullCaptureWait, "", nil
	}
	if ci != "" {
		return 0, "", fmt.Errorf("SPIKE_CAPTURE_WAIT_SECONDS is set and CI is set: a CI run must wait the full %s", fullCaptureWait)
	}
	n, perr := strconv.Atoi(v)
	if perr != nil || n < 0 {
		return 0, "", fmt.Errorf("SPIKE_CAPTURE_WAIT_SECONDS=%q is not a number of seconds", v)
	}
	return time.Duration(n) * time.Second, fmt.Sprintf("WARNING: the capture wait is %d seconds, not %s (SPIKE_CAPTURE_WAIT_SECONDS)", n, fullCaptureWait), nil
}

// The shared time limits of the tests fit in the 25 minute limit of go test:
// TestBifrost 15 minutes and TestI15PositiveControl 8 minutes.
const (
	suiteTimeout = 15 * time.Minute
	i15Timeout   = 8 * time.Minute
)

// clientName is the name of the MCP client. A client name has no hyphen.
const clientName = "helpdesk_test"

// clientID is the fixed ID of the MCP client.
const clientID = "helpdesk-test-client"

// toolName is the tool name that a caller sees: <client name>-<tool name>.
const toolName = clientName + "-" + mcpserver.ToolName

// suite is the shared state of the tests that use one Bifrost container set.
type suite struct {
	// ctx is the shared deadline of the test. It ends with the test.
	ctx     context.Context
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

	ctx, cancel := context.WithTimeout(t.Context(), suiteTimeout)
	defer cancel()
	stack, err := containers.Start(ctx, containers.Options{
		Secrets:   secrets,
		HostPorts: []int{mcp.Port(), model.Port()},
		ModelPort: model.Port(),
	})
	if err != nil {
		// The stack is nil here, so redact with the secrets of the run.
		t.Fatalf("start the container set: %v", containers.RedactSecrets(err.Error(), secrets))
	}
	defer stack.Close()

	s := &suite{
		ctx:     ctx,
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
	r, err := s.api.Do(s.ctx, bifrostapi.Request{Method: method, Path: path, Body: body})
	s.must(t, err)
	return r
}

// call sends a call with the given headers and without admin credentials.
func (s *suite) call(t *testing.T, method, path string, headers map[string]string, body any) *bifrostapi.Response {
	t.Helper()
	r, err := s.api.Do(s.ctx, bifrostapi.Request{
		Method: method, Path: path, Headers: headers, Body: body, NoAdmin: true,
	})
	s.must(t, err)
	return r
}

// The wait of I14 is the full wait in a CI run. A CI run that sets
// SPIKE_CAPTURE_WAIT_SECONDS fails.
func TestCaptureWaitFrom(t *testing.T) {
	if d, _, err := captureWaitFrom("true", ""); err != nil || d != fullCaptureWait {
		t.Errorf("CI set, no variable: %v, %v, want %v, nil", d, err, fullCaptureWait)
	}
	if d, _, err := captureWaitFrom("", ""); err != nil || d != fullCaptureWait {
		t.Errorf("no CI, no variable: %v, %v, want %v, nil", d, err, fullCaptureWait)
	}
	if _, _, err := captureWaitFrom("true", "1"); err == nil {
		t.Errorf("CI and the variable are set: want an error")
	}
	d, warn, err := captureWaitFrom("", "5")
	if err != nil || d != 5*time.Second || warn == "" {
		t.Errorf("local variable: %v, %q, %v, want 5s, a warning, nil", d, warn, err)
	}
	if _, _, err := captureWaitFrom("", "x"); err == nil {
		t.Errorf("a bad number: want an error")
	}
}
