//go:build integration

package bifrost

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/techorionai/constellation-techorion-ai/resources/test/bifrostapi"
	"github.com/techorionai/constellation-techorion-ai/resources/test/capture"
	"github.com/techorionai/constellation-techorion-ai/resources/test/containers"
	"github.com/techorionai/constellation-techorion-ai/resources/test/modelserver"
)

// I14: wait after the last call, stop the capture, and run the analyzer on the
// full capture. Bifrost made no call to a peer or a DNS name that is not in the
// allow list.
func (s *suite) i14Egress(t *testing.T) {
	ctx := s.ctx
	wait := captureWait(t)
	t.Logf("wait %s for the background jobs of Bifrost", wait)
	if err := sleep(ctx, wait); err != nil {
		t.Fatalf("the wait for the background jobs of Bifrost ended early: %v", err)
	}

	if !s.stack.Capture.IsRunning() {
		t.Fatal("the capture container does not run at the end of the test")
	}
	if !s.stack.Bifrost.IsRunning() {
		t.Fatal("the Bifrost container does not run at the end of the test")
	}
	pcap, err := s.stack.StopCapture(ctx)
	s.must(t, err)
	local, err := s.stack.LocalAddrs(ctx)
	s.must(t, err)
	allow, err := s.stack.Allow()
	s.must(t, err)
	res, err := capture.Analyze(bytes.NewReader(pcap), local, allow)
	s.must(t, err)
	t.Logf("capture: %d packets, %d bytes", res.Packets, len(pcap))
	t.Logf("outbound peers: %v", res.Peers)
	t.Logf("DNS names: %v", res.DNSNames)
	if len(res.UnexpectedPeers) != 0 {
		t.Errorf("unexpected outbound peers: %v", res.UnexpectedPeers)
	}
	if len(res.UnexpectedDNSNames) != 0 {
		t.Errorf("unexpected DNS names: %v", res.UnexpectedDNSNames)
	}
	if len(res.OtherProtocols) != 0 {
		t.Errorf("outbound packets that are not TCP and not UDP: %v", res.OtherProtocols)
	}
	// The capture must show the calls that we expect. If it does not, a pass
	// means nothing.
	pg := netip.AddrPortFrom(netip.MustParseAddr(s.stack.PGIP), 5432)
	if !slices.Contains(res.Peers, pg) {
		t.Errorf("the capture does not show Bifrost calls to PostgreSQL %v", pg)
	}
	if !slices.Contains(res.DNSNames, containers.PGAlias) {
		t.Errorf("the capture does not show the DNS query for %s", containers.PGAlias)
	}
}

// I15: positive control. A helper container in the capture namespace asks the
// Docker DNS for getbifrost.ai and opens a TCP connection to 1.1.1.1:443. The
// analyzer must report both. This shows that the capture sees DNS names and
// outbound calls from the namespace. This test has its own containers.
func TestI15PositiveControl(t *testing.T) {
	secrets, err := bifrostapi.NewSecrets()
	if err != nil {
		t.Fatal(err)
	}
	model, err := modelserver.Start(toolName, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	defer model.Close()

	ctx, cancel := context.WithTimeout(t.Context(), i15Timeout)
	defer cancel()
	stack, err := containers.Start(ctx, containers.Options{
		Secrets:   secrets,
		HostPorts: []int{model.Port()},
		ModelPort: model.Port(),
	})
	if err != nil {
		// The stack is nil here, so redact with the secrets of the run.
		t.Fatalf("start the container set: %v", containers.RedactSecrets(err.Error(), secrets))
	}
	defer stack.Close()
	if err := stack.WaitHealthy(ctx, 3*time.Minute); err != nil {
		t.Fatal(stack.Redact(err.Error()))
	}

	out, err := stack.RunInCaptureNamespace(ctx, "nslookup getbifrost.ai; nc -z -w 3 1.1.1.1 443; true")
	if err != nil {
		t.Fatal(stack.Redact(err.Error()))
	}
	t.Logf("helper output:\n%s", stack.Redact(out))
	if err := sleep(ctx, 2*time.Second); err != nil {
		t.Fatal(err)
	}

	pcap, err := stack.StopCapture(ctx)
	if err != nil {
		t.Fatal(stack.Redact(err.Error()))
	}
	local, err := stack.LocalAddrs(ctx)
	if err != nil {
		t.Fatal(stack.Redact(err.Error()))
	}
	allow, err := stack.Allow()
	if err != nil {
		t.Fatal(stack.Redact(err.Error()))
	}
	res, err := capture.Analyze(bytes.NewReader(pcap), local, allow)
	if err != nil {
		t.Fatal(stack.Redact(err.Error()))
	}
	t.Logf("unexpected peers: %v, unexpected DNS names: %v", res.UnexpectedPeers, res.UnexpectedDNSNames)
	if !slices.Contains(res.UnexpectedDNSNames, "getbifrost.ai") {
		t.Errorf("the analyzer did not report the DNS name getbifrost.ai: %v", res.UnexpectedDNSNames)
	}
	if !slices.Contains(res.UnexpectedPeers, netip.MustParseAddrPort("1.1.1.1:443")) {
		t.Errorf("the analyzer did not report the peer 1.1.1.1:443: %v", res.UnexpectedPeers)
	}
}
