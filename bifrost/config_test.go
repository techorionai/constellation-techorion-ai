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
		// The file is for production. The test sets ssl_mode: disable in its own
		// copy of the file.
		switch v := get(t, cfg, store, "config", "ssl_mode"); v {
		case "require", "verify-ca", "verify-full":
		default:
			t.Errorf("%s.config.ssl_mode is %v, want require, verify-ca, or verify-full", store, v)
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

// isSecretField reports whether a field must hold an env. value. The name
// filter finds password, secret, token, key, and credential fields. The field
// value in an object of a keys array is a provider key.
func isSecretField(path, key string) bool {
	return secretName.MatchString(key) || (key == "value" && strings.Contains(path, ".keys["))
}

// secretProblems returns a text for each secret field that is not an env.
// value and for each string that looks like a secret. It also returns the
// number of secret fields that it examined.
func secretProblems(cfg map[string]any) (problems []string, count int) {
	longRandom := regexp.MustCompile(`^[A-Za-z0-9+/=_-]{32,}$`)
	walk(cfg, "", "", func(path, key, value string) {
		if isSecretField(path, key) {
			count++
			if !strings.HasPrefix(value, "env.") {
				problems = append(problems, path+" is not an env. value")
			}
		}
		if longRandom.MatchString(value) && !strings.HasPrefix(value, "env.") {
			problems = append(problems, path+" looks like a secret value")
		}
	})
	return problems, count
}

// U3: each password, key, and token field is an env. value. No string looks
// like a secret.
func TestU3NoSecrets(t *testing.T) {
	problems, count := secretProblems(loadConfig(t))
	for _, p := range problems {
		t.Error(p)
	}
	if count == 0 {
		t.Fatalf("the test found no secret field: the name filter is wrong")
	}
}

// U3 must find a short literal provider key in keys[].value. The name filter
// alone does not match the field value.
func TestU3FindsLiteralProviderKey(t *testing.T) {
	var cfg map[string]any
	raw := `{"providers":{"openai":{"keys":[{"name":"k","value":"sk-short","models":["m"]}]}}}`
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	problems, count := secretProblems(cfg)
	if count != 1 || len(problems) != 1 {
		t.Errorf("count %d, problems %v, want one secret field and one problem", count, problems)
	}
	raw = `{"providers":{"openai":{"keys":[{"name":"k","value":"env.X","models":["m"]}]}}}`
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if problems, _ := secretProblems(cfg); len(problems) != 0 {
		t.Errorf("problems %v for an env. value", problems)
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
