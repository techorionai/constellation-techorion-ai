package containers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	dnet "github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/techorionai/constellation-techorion-ai/resources/test/bifrostapi"
	"github.com/techorionai/constellation-techorion-ai/resources/test/capture"
)

const (
	// BifrostPort is the HTTP port of Bifrost in the container.
	BifrostPort = "8080/tcp"
	// PGAlias is the network alias of PostgreSQL.
	PGAlias = "postgres"
	// HostInternal is the name of the test host in the capture namespace.
	HostInternal = testcontainers.HostInternal
	// PCAPPath is the path of the capture file in the capture container.
	PCAPPath = "/capture/run.pcap"
	// TcpdumpErrPath is the path of the file with the messages of tcpdump. At
	// the end of the capture it has the packet counts.
	TcpdumpErrPath = "/capture/tcpdump.err"
	// DatabaseName is the name of the Bifrost database and role.
	DatabaseName = "bifrost"
)

// Stack is a running set of containers: the network, PostgreSQL, the capture
// container, and Bifrost in the network namespace of the capture container.
type Stack struct {
	Network *testcontainers.DockerNetwork
	Secrets bifrostapi.Secrets

	PG      testcontainers.Container
	PGIP    string
	PGPort  string // mapped port on the test host
	PGHost  string
	Capture testcontainers.Container
	Bifrost testcontainers.Container

	// HostIP is the IP address of the host access container.
	HostIP string
	// HostPorts are the test-process ports that the containers can reach.
	HostPorts []int
	// BaseURL is the URL of Bifrost on the test host.
	BaseURL string
	// SynToPGBeforeBifrost is the number of TCP SYN packets to PostgreSQL port
	// 5432 in the capture before Bifrost started.
	SynToPGBeforeBifrost int

	extraSecrets []string
	cleanups     []func()
}

// Options set the start of a stack.
type Options struct {
	Secrets bifrostapi.Secrets
	// HostPorts are the ports of the test process that Bifrost must reach.
	HostPorts []int
	// ModelPort is the port of the scripted model server in HostPorts.
	ModelPort int
}

// Start starts the stack in this order: network, PostgreSQL, capture container
// (and a wait for the capture file), Bifrost. Call Close to stop it.
func Start(ctx context.Context, o Options) (*Stack, error) {
	s := &Stack{Secrets: o.Secrets, HostPorts: o.HostPorts}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()

	nw, err := network.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("containers: network: %w", err)
	}
	s.Network = nw
	s.cleanups = append(s.cleanups, func() { _ = nw.Remove(context.Background()) })

	if err := s.startPostgres(ctx); err != nil {
		return nil, err
	}
	if err := s.startCapture(ctx); err != nil {
		return nil, err
	}
	if err := s.startBifrost(ctx, o); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

// Close stops and removes all containers and the network.
func (s *Stack) Close() {
	for i := len(s.cleanups) - 1; i >= 0; i-- {
		s.cleanups[i]()
	}
	s.cleanups = nil
}

func (s *Stack) track(c testcontainers.Container) {
	s.cleanups = append(s.cleanups, func() { _ = testcontainers.TerminateContainer(c) })
}

func (s *Stack) startPostgres(ctx context.Context) error {
	req := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        PostgresImage,
			ExposedPorts: []string{"5432/tcp"},
			Env:          map[string]string{"POSTGRES_PASSWORD": s.Secrets.PGAdminPassword},
			Networks:     []string{s.Network.Name},
			NetworkAliases: map[string][]string{
				s.Network.Name: {PGAlias},
			},
			HostConfigModifier: func(hc *container.HostConfig) {
				publishOnLoopback(hc, "5432/tcp")
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	}
	c, err := testcontainers.GenericContainer(ctx, req)
	if c != nil {
		s.track(c)
	}
	if err != nil {
		return fmt.Errorf("containers: start postgres: %w", err)
	}
	s.PG = c
	// Same isolation as the provisioning of constellation-deploy: one database,
	// one role, and no CONNECT for PUBLIC.
	sql := []string{
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", DatabaseName, s.Secrets.PGBifrostPassword),
		fmt.Sprintf("CREATE DATABASE %s OWNER %s", DatabaseName, DatabaseName),
		fmt.Sprintf("REVOKE CONNECT ON DATABASE %s FROM PUBLIC", DatabaseName),
	}
	cmd := []string{"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1"}
	for _, q := range sql {
		cmd = append(cmd, "-c", q)
	}
	if out, err := execOK(ctx, c, cmd); err != nil {
		return fmt.Errorf("containers: provision postgres: %w: %s", err, redact(out, s.Secrets, nil))
	}
	ip, err := containerIP(ctx, c, s.Network.Name)
	if err != nil {
		return err
	}
	s.PGIP = ip
	host, err := c.Host(ctx)
	if err != nil {
		return fmt.Errorf("containers: postgres host: %w", err)
	}
	p, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return fmt.Errorf("containers: postgres mapped port: %w", err)
	}
	s.PGHost, s.PGPort = host, strconv.Itoa(int(p.Num()))
	return nil
}

// publishOnLoopback publishes a container port on 127.0.0.1 of the test host
// only. The traffic of the test stack is plain text, so no other host can reach
// it.
func publishOnLoopback(hc *container.HostConfig, port string) {
	if hc.PortBindings == nil {
		hc.PortBindings = dnet.PortMap{}
	}
	hc.PortBindings[dnet.MustParsePort(port)] = []dnet.PortBinding{
		{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: "0"},
	}
}

// PGConnString returns the connection string of the Bifrost role from the test
// host.
func (s *Stack) PGConnString() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		DatabaseName, s.Secrets.PGBifrostPassword, s.PGHost, s.PGPort, DatabaseName)
}

func (s *Stack) startCapture(ctx context.Context) error {
	// The filter takes all IP packets, so a packet of any protocol (for example
	// ICMP) is in the file and the analyzer reports it.
	script := "mkdir -p /capture; " +
		"tcpdump -i any -nn -U -s 512 -w " + PCAPPath + " ip or ip6 2>" + TcpdumpErrPath + " & " +
		"wait; tail -f /dev/null"
	req := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        CaptureImage,
			Entrypoint:   []string{"sh", "-c", script},
			ExposedPorts: []string{BifrostPort},
			Networks:     []string{s.Network.Name},
			NetworkAliases: map[string][]string{
				s.Network.Name: {"bifrost"},
			},
			HostAccessPorts: s.HostPorts,
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.CapAdd = append(hc.CapAdd, "NET_RAW", "NET_ADMIN")
				publishOnLoopback(hc, BifrostPort)
			},
		},
		Started: true,
	}
	c, err := testcontainers.GenericContainer(ctx, req)
	if c != nil {
		s.track(c)
	}
	if err != nil {
		return fmt.Errorf("containers: start capture: %w", err)
	}
	s.Capture = c

	// Find the host access container. It is the target of host.testcontainers.internal.
	if len(s.HostPorts) > 0 {
		out, err := execOK(ctx, c, []string{"getent", "hosts", HostInternal})
		if err != nil {
			return fmt.Errorf("containers: resolve %s: %w", HostInternal, err)
		}
		f := strings.Fields(out)
		if len(f) == 0 {
			return fmt.Errorf("containers: no address for %s", HostInternal)
		}
		s.HostIP = f[0]
	}

	// Make traffic in the namespace and wait until tcpdump has written it.
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, _ = execOK(ctx, c, []string{"nc", "-z", "-w", "1", s.PGIP, "5432"})
		sizeOut, serr := execOK(ctx, c, []string{"stat", "-c", "%s", PCAPPath})
		if serr == nil {
			if n, perr := strconv.Atoi(strings.TrimSpace(sizeOut)); perr == nil && n > 24+16 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			errOut, _ := execOK(ctx, c, []string{"cat", TcpdumpErrPath})
			return fmt.Errorf("containers: tcpdump wrote no data: %s", errOut)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *Stack) startBifrost(ctx context.Context, o Options) error {
	n, err := s.PGSynCount(ctx)
	if err != nil {
		return err
	}
	s.SynToPGBeforeBifrost = n
	cfg, err := os.ReadFile(repoPath("bifrost", "config.json"))
	if err != nil {
		return fmt.Errorf("containers: read config.json: %w", err)
	}
	cfg, err = testConfig(cfg, fmt.Sprintf("http://%s:%d", HostInternal, o.ModelPort))
	if err != nil {
		return err
	}
	files := []testcontainers.ContainerFile{{
		Reader:            bytes.NewReader(cfg),
		ContainerFilePath: "/app/data/config.json",
		FileMode:          0o644,
	}}
	for _, name := range []string{"pricing.json", "model-parameters.json", "servers.json"} {
		files = append(files, testcontainers.ContainerFile{
			HostFilePath:      repoPath("bifrost", "local-data", name),
			ContainerFilePath: "/app/local-data/" + name,
			FileMode:          0o444,
		})
	}
	env := map[string]string{
		"BIFROST_ENCRYPTION_KEY": s.Secrets.EncryptionKey,
		"BIFROST_SETUP_TOKEN":    s.Secrets.SetupToken,
		"BIFROST_ADMIN_USERNAME": s.Secrets.AdminUser,
		"BIFROST_ADMIN_PASSWORD": s.Secrets.AdminPassword,
		"BIFROST_DB_HOST":        PGAlias,
		"BIFROST_DB_PORT":        "5432",
		"BIFROST_DB_USER":        DatabaseName,
		"BIFROST_DB_PASSWORD":    s.Secrets.PGBifrostPassword,
		"BIFROST_OPENAI_API_KEY": s.Secrets.OpenAIKey,
	}
	capID := s.Capture.GetContainerID()
	req := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: BifrostImage,
			Env:   env,
			Files: files,
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.NetworkMode = container.NetworkMode("container:" + capID)
			},
		},
		Started: true,
	}
	c, err := testcontainers.GenericContainer(ctx, req)
	if c != nil {
		s.track(c)
	}
	if err != nil {
		return fmt.Errorf("containers: start bifrost: %w", err)
	}
	s.Bifrost = c

	host, err := s.Capture.Host(ctx)
	if err != nil {
		return fmt.Errorf("containers: capture host: %w", err)
	}
	p, err := s.Capture.MappedPort(ctx, BifrostPort)
	if err != nil {
		return fmt.Errorf("containers: capture mapped port: %w", err)
	}
	s.BaseURL = fmt.Sprintf("http://%s:%d", host, p.Num())
	return nil
}

// PGSynCount returns the number of TCP SYN packets (without ACK) to PostgreSQL
// port 5432 in the capture file so far.
func (s *Stack) PGSynCount(ctx context.Context) (int, error) {
	// The shell stops with an error when tcpdump fails. A pipe from tcpdump to
	// wc would hide the exit code of tcpdump and give a count of 0.
	out, err := execOK(ctx, s.Capture, []string{"sh", "-c",
		"out=$(tcpdump -nn -r " + PCAPPath + " 'tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn and dst port 5432' 2>/dev/null) || exit 1; " +
			"printf '%s\\n' \"$out\" | grep -c . || true"})
	if err != nil {
		return 0, fmt.Errorf("containers: count SYN packets: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("containers: count SYN packets: %w", err)
	}
	return n, nil
}

// WaitHealthy waits until GET /health returns 200.
func (s *Stack) WaitHealthy(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{Timeout: 5 * time.Second}
	var last error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL+"/health", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			logs, _ := s.BifrostLogs(context.Background())
			return fmt.Errorf("containers: bifrost not healthy: %w (last: %w)\nlogs:\n%s", ctx.Err(), last, s.Redact(tail(logs, 4000)))
		case <-time.After(time.Second):
		}
	}
}

// BifrostLogs returns the logs of the Bifrost container.
func (s *Stack) BifrostLogs(ctx context.Context) (string, error) {
	r, err := s.Bifrost.Logs(ctx)
	if err != nil {
		return "", err
	}
	defer r.Close() //nolint:errcheck
	b, err := io.ReadAll(r)
	return string(b), err
}

// BifrostExec runs a command in the Bifrost container and returns the output.
func (s *Stack) BifrostExec(ctx context.Context, cmd ...string) (string, error) {
	return execOK(ctx, s.Bifrost, cmd)
}

// LocalAddrs returns the IP addresses of the capture namespace, including the
// loopback addresses.
func (s *Stack) LocalAddrs(ctx context.Context) ([]netip.Addr, error) {
	out, err := execOK(ctx, s.Capture, []string{"ip", "-o", "addr", "show"})
	if err != nil {
		return nil, fmt.Errorf("containers: list addresses: %w", err)
	}
	var addrs []netip.Addr
	for sc := bufio.NewScanner(strings.NewReader(out)); sc.Scan(); {
		f := strings.Fields(sc.Text())
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" || f[i] == "inet6" {
				p, perr := netip.ParsePrefix(f[i+1])
				if perr != nil {
					return nil, fmt.Errorf("containers: parse address %q: %w", f[i+1], perr)
				}
				addrs = append(addrs, p.Addr())
			}
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("containers: the capture namespace has no address")
	}
	return addrs, nil
}

// Allow returns the allow list for the analyzer: PostgreSQL, the host access
// container with the test ports, and the DNS names of both.
func (s *Stack) Allow() (capture.Allow, error) {
	pg, err := netip.ParseAddr(s.PGIP)
	if err != nil {
		return capture.Allow{}, fmt.Errorf("containers: postgres ip: %w", err)
	}
	a := capture.Allow{
		Peers:    []netip.AddrPort{netip.AddrPortFrom(pg, 5432)},
		DNSNames: []string{PGAlias, HostInternal},
	}
	if s.HostIP != "" {
		h, err := netip.ParseAddr(s.HostIP)
		if err != nil {
			return capture.Allow{}, fmt.Errorf("containers: host ip: %w", err)
		}
		for _, p := range s.HostPorts {
			a.Peers = append(a.Peers, netip.AddrPortFrom(h, uint16(p))) //nolint:gosec
		}
	}
	return a, nil
}

// StopCapture stops tcpdump with SIGINT, waits for it to end, and returns the
// pcap file. The capture container keeps running.
func (s *Stack) StopCapture(ctx context.Context) ([]byte, error) {
	if !s.Capture.IsRunning() {
		return nil, errors.New("containers: the capture container is not running")
	}
	if _, err := execOK(ctx, s.Capture, []string{"pkill", "-INT", "tcpdump"}); err != nil {
		return nil, fmt.Errorf("containers: stop tcpdump: %w", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := execOK(ctx, s.Capture, []string{"pgrep", "tcpdump"}); err != nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, errors.New("containers: tcpdump did not stop")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// A packet that the kernel dropped can hide a call. Fail if tcpdump dropped
	// any packet, and fail if the count is not in the messages of tcpdump.
	msgs, err := execOK(ctx, s.Capture, []string{"cat", TcpdumpErrPath})
	if err != nil {
		return nil, fmt.Errorf("containers: read tcpdump messages: %w", err)
	}
	dropped, err := DroppedByKernel(msgs)
	if err != nil {
		return nil, err
	}
	if dropped > 0 {
		return nil, fmt.Errorf("containers: tcpdump: the kernel dropped %d packets, the capture is not complete", dropped)
	}
	r, err := s.Capture.CopyFileFromContainer(ctx, PCAPPath)
	if err != nil {
		return nil, fmt.Errorf("containers: copy pcap: %w", err)
	}
	defer r.Close() //nolint:errcheck
	return io.ReadAll(r)
}

// RunInCaptureNamespace runs a short-lived helper container in the network
// namespace of the capture container and returns its output.
func (s *Stack) RunInCaptureNamespace(ctx context.Context, script string) (string, error) {
	capID := s.Capture.GetContainerID()
	req := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      CaptureImage,
			Entrypoint: []string{"sh", "-c", script},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.NetworkMode = container.NetworkMode("container:" + capID)
			},
			WaitingFor: wait.ForExit().WithExitTimeout(90 * time.Second),
		},
		Started: true,
	}
	c, err := testcontainers.GenericContainer(ctx, req)
	if c != nil {
		defer func() { _ = testcontainers.TerminateContainer(c) }()
	}
	if err != nil {
		return "", fmt.Errorf("containers: helper: %w", err)
	}
	r, err := c.Logs(ctx)
	if err != nil {
		return "", err
	}
	defer r.Close() //nolint:errcheck
	b, err := io.ReadAll(r)
	return string(b), err
}

var droppedRe = regexp.MustCompile(`(?m)^(\d+) packets? dropped by kernel`)

// DroppedByKernel reads the number of packets that the kernel dropped from the
// messages that tcpdump writes when it ends. It returns an error when the
// messages have no such line, because then the capture can not prove anything.
func DroppedByKernel(msgs string) (int, error) {
	m := droppedRe.FindStringSubmatch(msgs)
	if m == nil {
		return 0, fmt.Errorf("containers: the tcpdump messages have no drop count: %q", tail(msgs, 300))
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("containers: tcpdump drop count: %w", err)
	}
	return n, nil
}

func execOK(ctx context.Context, c testcontainers.Container, cmd []string) (string, error) {
	code, r, err := c.Exec(ctx, cmd, tcexec.Multiplexed())
	var out string
	if r != nil {
		b, _ := io.ReadAll(r)
		out = string(b)
	}
	if err != nil {
		return out, err
	}
	if code != 0 {
		return out, fmt.Errorf("%v exited with code %d", cmd[:min(len(cmd), 2)], code)
	}
	return out, nil
}

// Exec runs a command in a container and returns the output. It fails on a
// non-zero exit code.
func Exec(ctx context.Context, c testcontainers.Container, cmd ...string) (string, error) {
	return execOK(ctx, c, cmd)
}

func containerIP(ctx context.Context, c testcontainers.Container, networkName string) (string, error) {
	info, err := c.Inspect(ctx)
	if err != nil {
		return "", fmt.Errorf("containers: inspect: %w", err)
	}
	n, ok := info.NetworkSettings.Networks[networkName]
	if !ok || !n.IPAddress.IsValid() {
		return "", fmt.Errorf("containers: no address on network %s", networkName)
	}
	return n.IPAddress.String(), nil
}

// testConfig makes the copy of config.json that goes into the container. It
// sets values that are for the test only and that the file in the repository
// does not have:
//   - providers.openai.network_config.base_url and allow_private_network: the
//     scripted model server has a private address. The field does not accept an
//     env. value, and the management API refuses a private address.
//   - ssl_mode: disable in both stores: the test network has no TLS for
//     PostgreSQL. The file in the repository has a value with TLS.
func testConfig(cfg []byte, baseURL string) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		return nil, fmt.Errorf("containers: parse config.json: %w", err)
	}
	providers, _ := m["providers"].(map[string]any)
	openai, _ := providers["openai"].(map[string]any)
	nc, _ := openai["network_config"].(map[string]any)
	if nc == nil {
		return nil, errors.New("containers: config.json has no providers.openai.network_config")
	}
	nc["base_url"] = baseURL
	nc["allow_private_network"] = true
	for _, store := range []string{"config_store", "logs_store"} {
		st, _ := m[store].(map[string]any)
		sc, _ := st["config"].(map[string]any)
		if sc == nil {
			return nil, fmt.Errorf("containers: config.json has no %s.config", store)
		}
		sc["ssl_mode"] = "disable"
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("containers: encode config.json: %w", err)
	}
	return out, nil
}

// repoPath returns a path in the repository, found from the working directory
// of the test.
func repoPath(parts ...string) string {
	dir, err := os.Getwd()
	if err != nil {
		return filepath.Join(parts...)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(append([]string{dir}, parts...)...)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Join(parts...)
		}
		dir = parent
	}
}

// redact removes the secret values of a run from a text, so the text can go
// to a test log. It removes only the listed values and not other hex strings,
// so container IDs and image digests stay for debug.
func redact(s string, sec bifrostapi.Secrets, extra []string) string {
	vals := append([]string{
		sec.AdminPassword, sec.SetupToken, sec.EncryptionKey, sec.PGAdminPassword,
		sec.PGBifrostPassword, sec.OpenAIKey, sec.TokenA, sec.TokenB, sec.TokenBad,
	}, extra...)
	for _, v := range vals {
		if v != "" {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
	}
	return s
}

// RedactSecrets removes the secret values from a text. Use it when no stack
// exists, for example when Start fails.
func RedactSecrets(text string, sec bifrostapi.Secrets) string { return redact(text, sec, nil) }

// Redact removes the secret values of the stack from a text. This includes the
// values that AddSecret registered.
func (s *Stack) Redact(text string) string { return redact(text, s.Secrets, s.extraSecrets) }

// AddSecret registers a secret value that the test made during the run, for
// example a virtual key, so that Redact removes it.
func (s *Stack) AddSecret(v string) {
	if v != "" {
		s.extraSecrets = append(s.extraSecrets, v)
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
