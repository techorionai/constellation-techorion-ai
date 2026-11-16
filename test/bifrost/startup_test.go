//go:build integration

package bifrost

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/techorionai/constellation-techorion-ai/resources/test/bifrostapi"
	"github.com/techorionai/constellation-techorion-ai/resources/test/containers"
)

// I1: start the network, PostgreSQL, the capture container, and Bifrost in the
// capture namespace. Wait for /health.
func (s *suite) i1Startup(t *testing.T) {
	ctx := context.Background()
	s.must(t, s.stack.WaitHealthy(ctx, 3*time.Minute))

	// The tables of Bifrost are in the bifrost database (PostgreSQL stores).
	conn, err := pgx.Connect(ctx, s.stack.PGConnString())
	s.must(t, err)
	defer conn.Close(ctx) //nolint:errcheck
	for _, table := range []string{"config_mcp_clients", "governance_config"} {
		var exists bool
		err := conn.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)`,
			table).Scan(&exists)
		s.must(t, err)
		if !exists {
			t.Errorf("the bifrost database has no table %s", table)
		}
	}

	// Bifrost made no SQLite file.
	out, err := s.stack.BifrostExec(ctx, "sh", "-c", "ls -A /app/data; ls -A /app")
	s.must(t, err)
	for _, name := range []string{"config.db", "logs.db"} {
		if strings.Contains(out, name) {
			t.Errorf("the application directory has the file %s:\n%s", name, out)
		}
	}

	// The capture file had data before Bifrost started (the start of the stack
	// waits for it). It has the first TCP SYN from Bifrost to PostgreSQL port 5432.
	size, err := containers.Exec(ctx, s.stack.Capture, "stat", "-c", "%s", containers.PCAPPath)
	s.must(t, err)
	t.Logf("capture file size after start: %s", strings.TrimSpace(size))
	after, err := s.stack.PGSynCount(ctx)
	s.must(t, err)
	if after <= s.stack.SynToPGBeforeBifrost {
		t.Errorf("TCP SYN packets to PostgreSQL port 5432: %d before Bifrost, %d after: the capture does not show the connection of Bifrost", s.stack.SynToPGBeforeBifrost, after)
	}
}

// I2: switch the news feed off, then read the feed.
func (s *suite) i2NewsFeedSwitch(t *testing.T) {
	put := s.admin(t, "PUT", "/api/rss/settings", map[string]any{"enabled": false})
	if put.Status != 200 {
		t.Fatalf("PUT /api/rss/settings: %d %s", put.Status, put.Body)
	}
	get := s.admin(t, "GET", "/api/rss/items", nil)
	t.Logf("GET /api/rss/items: %d %s", get.Status, get.Body)
	if get.Status != 200 {
		t.Fatalf("GET /api/rss/items: %d %s", get.Status, get.Body)
	}
	var v any
	s.must(t, json.Unmarshal(get.Body, &v))
	if !emptyList(v) {
		t.Errorf("the feed is not empty: %s", get.Body)
	}
}

// emptyList reports whether a decoded JSON value is an empty list or an object
// whose list fields are all empty.
func emptyList(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []any:
		return len(x) == 0
	case map[string]any:
		for k, f := range x {
			if arr, ok := f.([]any); ok {
				if len(arr) != 0 {
					return false
				}
				continue
			}
			if k == "items" && f != nil {
				return false
			}
		}
		return true
	}
	return false
}

// I3: a management call without credentials.
func (s *suite) i3NoCredentials(t *testing.T) {
	r := s.call(t, "GET", "/api/mcp/clients", nil, nil)
	if r.Status != 401 {
		t.Errorf("GET /api/mcp/clients without credentials: %d %s, want 401", r.Status, r.Body)
	}
}

// I18: a management call with the admin user and a wrong password.
func (s *suite) i18WrongPassword(t *testing.T) {
	r, err := s.api.Do(context.Background(), bifrostapi.Request{
		Method: "GET", Path: "/api/mcp/clients",
		AdminUser: s.secrets.AdminUser, AdminPass: bifrostapi.MustRandomSecret(),
	})
	s.must(t, err)
	if r.Status != 401 {
		t.Errorf("GET /api/mcp/clients with a wrong password: %d %s, want 401", r.Status, r.Body)
	}
}
