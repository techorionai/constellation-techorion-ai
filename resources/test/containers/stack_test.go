package containers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/techorionai/constellation-techorion-ai/resources/test/bifrostapi"
)

// The drop count of tcpdump must be 0, and a missing count is an error.
func TestDroppedByKernel(t *testing.T) {
	ok := "12 packets captured\n12 packets received by filter\n0 packets dropped by kernel\n"
	if n, err := DroppedByKernel(ok); err != nil || n != 0 {
		t.Errorf("got %d, %v, want 0, nil", n, err)
	}
	bad := "120 packets captured\n125 packets received by filter\n5 packets dropped by kernel\n"
	if n, err := DroppedByKernel(bad); err != nil || n != 5 {
		t.Errorf("got %d, %v, want 5, nil", n, err)
	}
	if _, err := DroppedByKernel("tcpdump: listening on any\n"); err == nil {
		t.Errorf("no error for messages without a drop count")
	}
	if _, err := DroppedByKernel(""); err == nil {
		t.Errorf("no error for empty messages")
	}
}

// The configuration of the repository has TLS for PostgreSQL. Only the copy for
// the test sets ssl_mode: disable, and it sets base_url.
func TestTestConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "bifrost", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"disable"`) {
		t.Fatalf("bifrost/config.json has a disable value")
	}
	out, err := testConfig(raw, "http://host.example:1234")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	for _, store := range []string{"config_store", "logs_store"} {
		cfg := m[store].(map[string]any)["config"].(map[string]any)
		if cfg["ssl_mode"] != "disable" {
			t.Errorf("%s ssl_mode is %v in the test copy, want disable", store, cfg["ssl_mode"])
		}
	}
	nc := m["providers"].(map[string]any)["openai"].(map[string]any)["network_config"].(map[string]any)
	if nc["base_url"] != "http://host.example:1234" || nc["allow_private_network"] != true {
		t.Errorf("network_config %v has no test values", nc)
	}
}

// The redact function removes the listed values and keeps other hex strings.
func TestRedact(t *testing.T) {
	sec, err := bifrostapi.NewSecrets()
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 32)
	extra := "virtual-key-value-1"
	s := &Stack{Secrets: sec}
	s.AddSecret(extra)
	got := s.Redact("a " + sec.TokenA + " b " + extra + " c " + id)
	if strings.Contains(got, sec.TokenA) || strings.Contains(got, extra) {
		t.Errorf("a secret is in %q", got)
	}
	if !strings.Contains(got, id) {
		t.Errorf("the container ID is not in %q", got)
	}
	if strings.Contains(RedactSecrets("x "+sec.AdminPassword, sec), sec.AdminPassword) {
		t.Errorf("RedactSecrets keeps a secret")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found")
		}
		dir = parent
	}
}
