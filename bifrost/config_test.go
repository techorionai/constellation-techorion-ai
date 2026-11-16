// Package bifrost has no code. It holds the configuration files for the Bifrost
// spike and the unit tests that examine them.
package bifrost

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func loadConfig(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("config.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("config.json is not valid JSON: %v", err)
	}
	return m
}

// get returns the value at a path of object keys.
func get(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %q is not in an object", path, p)
		}
		cur, ok = obj[p]
		if !ok {
			t.Fatalf("path %v: the key %q is missing", path, p)
		}
	}
	return cur
}

// U1: the outbound settings.
func TestU1OutboundSettings(t *testing.T) {
	cfg := loadConfig(t)
	for _, k := range []string{"pricing_url", "model_parameters_url", "mcp_library_url"} {
		v, ok := get(t, cfg, "framework", "pricing", k).(string)
		if !ok || !strings.HasPrefix(v, "file://") {
			t.Errorf("framework.pricing.%s is %v, want a file:// URL", k, v)
		}
	}
	for _, k := range []string{"mcp_library_sync_interval", "live_models_sync_interval"} {
		v, ok := get(t, cfg, "framework", "pricing", k).(float64)
		if !ok || v != 0 {
			t.Errorf("framework.pricing.%s is %v, want 0", k, v)
		}
	}
	if _, ok := cfg["plugins"]; ok {
		t.Errorf("config.json has a plugins entry")
	}
}

// U2: the stores and the authentication.
func TestU2StoresAndAuth(t *testing.T) {
	cfg := loadConfig(t)
	for _, store := range []string{"config_store", "logs_store"} {
		if v := get(t, cfg, store, "type"); v != "postgres" {
			t.Errorf("%s.type is %v, want postgres", store, v)
		}
		if v := get(t, cfg, store, "enabled"); v != true {
			t.Errorf("%s.enabled is %v, want true", store, v)
		}
	}
	if v := get(t, cfg, "client", "enforce_auth_on_inference"); v != true {
		t.Errorf("client.enforce_auth_on_inference is %v, want true", v)
	}
	if v := get(t, cfg, "governance", "auth_config", "is_enabled"); v != true {
		t.Errorf("governance.auth_config.is_enabled is %v, want true", v)
	}
}

var secretName = regexp.MustCompile(`(?i)(password|secret|token|key|credential)`)

// walk calls fn for each string value with the key name and the path.
func walk(v any, path string, key string, fn func(path, key, value string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			walk(c, path+"."+k, k, fn)
		}
	case []any:
		for i, c := range x {
			walk(c, fmt.Sprintf("%s[%d]", path, i), key, fn)
		}
	case string:
		fn(path, key, x)
	}
}

// U3: each password, key, and token field is an env. value. No string looks
// like a secret.
func TestU3NoSecrets(t *testing.T) {
	cfg := loadConfig(t)
	longRandom := regexp.MustCompile(`^[A-Za-z0-9+/=_-]{32,}$`)
	count := 0
	walk(cfg, "", "", func(path, key, value string) {
		if secretName.MatchString(key) {
			count++
			if !strings.HasPrefix(value, "env.") {
				t.Errorf("%s is not an env. value", path)
			}
		}
		if longRandom.MatchString(value) && !strings.HasPrefix(value, "env.") {
			t.Errorf("%s looks like a secret value", path)
		}
	})
	if count == 0 {
		t.Fatalf("the test found no secret field: the name filter is wrong")
	}
}

// U4: each file in local-data is valid JSON. The pricing and parameter files
// have models.
func TestU4LocalData(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("local-data", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"pricing.json": false, "model-parameters.json": false, "servers.json": false}
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // the path comes from a glob of the repository
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Errorf("%s is not a valid JSON object: %v", f, err)
			continue
		}
		name := filepath.Base(f)
		want[name] = true
		switch name {
		case "pricing.json", "model-parameters.json":
			if len(m) == 0 {
				t.Errorf("%s has no model", f)
			}
		case "servers.json":
			if s, ok := m["servers"].([]any); !ok || len(s) == 0 {
				t.Errorf("%s has no servers", f)
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("local-data/%s is missing", name)
		}
	}
}
