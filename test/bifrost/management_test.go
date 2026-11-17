//go:build integration

package bifrost

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// clientView is the part of GET /api/mcp/clients that the tests read.
type clientView struct {
	Clients []struct {
		Config struct {
			ClientID         string          `json:"client_id"`
			Name             string          `json:"name"`
			ConnectionString json.RawMessage `json:"connection_string"`
		} `json:"config"`
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	} `json:"clients"`
}

func (s *suite) listClients(t *testing.T) clientView {
	t.Helper()
	r := s.admin(t, "GET", "/api/mcp/clients", nil)
	if r.Status != 200 {
		t.Fatalf("GET /api/mcp/clients: %d %s", r.Status, s.stack.Redact(string(r.Body)))
	}
	var v clientView
	s.must(t, json.Unmarshal(r.Body, &v))
	return v
}

// storedURL returns the connection_string field of the first client, as JSON.
func (s *suite) storedURL(t *testing.T) string {
	t.Helper()
	v := s.listClients(t)
	if len(v.Clients) == 0 {
		t.Fatalf("the client list is empty")
	}
	return string(v.Clients[0].Config.ConnectionString)
}

// I12: management behavior that VISION 12.1 depends on. PUT does not change the
// connection string, refresh-tools works, reconnect returns 400 for this
// client, DELETE removes the client.
func (s *suite) i12ManagementBehavior(t *testing.T) {
	before := s.storedURL(t)

	put := s.admin(t, "PUT", "/api/mcp/client/"+clientID, map[string]any{
		"connection_string": strings.Replace(s.mcpURL(), "/mcp", "/other", 1),
	})
	t.Logf("RESULT I12 PUT status=%d body=%s", put.Status, s.stack.Redact(string(put.Body)))
	if put.Status != 200 {
		t.Errorf("PUT: %d %s, want 200", put.Status, s.stack.Redact(string(put.Body)))
	}
	if after := s.storedURL(t); after != before {
		t.Errorf("the stored connection string changed: %s -> %s", before, after)
	}

	mark := s.mcp.Mark()
	refresh := s.admin(t, "POST", "/api/mcp/client/"+clientID+"/refresh-tools", nil)
	refreshRecs := s.mcp.Since(mark)
	t.Logf("RESULT I12 MCP methods during refresh-tools: %v", rpcMethods(refreshRecs))
	t.Logf("RESULT I12 refresh-tools status=%d body=%s", refresh.Status, s.stack.Redact(string(refresh.Body)))
	if refresh.Status != 200 {
		t.Errorf("refresh-tools: %d %s, want 200", refresh.Status, s.stack.Redact(string(refresh.Body)))
	} else {
		m, err := refresh.JSON()
		s.must(t, err)
		if n, _ := m["tool_count"].(float64); n != 1 {
			t.Errorf("tool_count %v, want 1", m["tool_count"])
		}
	}

	if len(refreshRecs) == 0 {
		t.Errorf("the test MCP server got no request during refresh-tools")
	}
	for _, rec := range refreshRecs {
		if _, ok := rec.Authorization(); ok {
			t.Errorf("%s during refresh-tools has an Authorization header", rec.RPCMethod)
		}
	}

	reconnect := s.admin(t, "POST", "/api/mcp/client/"+clientID+"/reconnect", nil)
	t.Logf("RESULT I12 reconnect status=%d body=%s", reconnect.Status, s.stack.Redact(string(reconnect.Body)))
	if reconnect.Status != 400 {
		t.Errorf("reconnect: %d %s, want 400", reconnect.Status, s.stack.Redact(string(reconnect.Body)))
	}

	del := s.admin(t, "DELETE", "/api/mcp/client/"+clientID, nil)
	if del.Status != 200 {
		t.Errorf("DELETE: %d %s, want 200", del.Status, s.stack.Redact(string(del.Body)))
	}
	if v := s.listClients(t); len(v.Clients) != 0 {
		t.Errorf("the client list has %d clients after DELETE, want 0", len(v.Clients))
	}
}

// I13: the tokens are in no container log and in no text column of the
// bifrost database.
func (s *suite) i13NoTokenStored(t *testing.T) {
	ctx := s.ctx
	names := []string{"token A", "token B", "rejected token"}
	toks := []string{s.secrets.TokenA, s.secrets.TokenB, s.secrets.TokenBad}
	logs, err := s.stack.BifrostLogs(ctx)
	s.must(t, err)
	for i, tok := range toks {
		if strings.Contains(logs, tok) {
			t.Errorf("%s is in the Bifrost container log", names[i])
		}
	}
	t.Logf("Bifrost log size: %d bytes", len(logs))

	conn, err := pgx.Connect(ctx, s.stack.PGConnString())
	s.must(t, err)
	defer conn.Close(ctx) //nolint:errcheck
	rows, err := conn.Query(ctx, `
		SELECT c.table_name, c.column_name
		FROM information_schema.columns c
		JOIN information_schema.tables t
		  ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
		WHERE c.table_schema = 'public'
		  AND c.data_type IN ('text', 'character varying', 'character', 'json', 'jsonb')`)
	s.must(t, err)
	type col struct{ table, column string }
	var cols []col
	for rows.Next() {
		var c col
		s.must(t, rows.Scan(&c.table, &c.column))
		cols = append(cols, c)
	}
	s.must(t, rows.Err())
	if len(cols) == 0 {
		t.Fatalf("the database has no text column: the test cannot prove anything")
	}
	// Bifrost writes the request logs in batches. Wait until the logs table has
	// rows. A search in an empty table proves nothing.
	var logRows int64
	for deadline := time.Now().Add(90 * time.Second); ; {
		s.must(t, conn.QueryRow(ctx, `SELECT count(*) FROM logs`).Scan(&logRows))
		if logRows > 0 || time.Now().After(deadline) {
			break
		}
		s.must(t, sleep(ctx, 2*time.Second))
	}
	t.Logf("searched %d text columns, logs table rows: %d", len(cols), logRows)
	if logRows == 0 {
		t.Fatalf("the logs table has no rows: the search proves nothing")
	}
	// One query for each column counts the rows for the three tokens.
	for _, c := range cols {
		x := pgx.Identifier{c.column}.Sanitize() + "::text"
		q := fmt.Sprintf(`SELECT
			count(*) FILTER (WHERE position($1 in %[2]s) > 0),
			count(*) FILTER (WHERE position($2 in %[2]s) > 0),
			count(*) FILTER (WHERE position($3 in %[2]s) > 0)
			FROM %[1]s`, pgx.Identifier{c.table}.Sanitize(), x)
		var n [3]int
		s.must(t, conn.QueryRow(ctx, q, toks[0], toks[1], toks[2]).Scan(&n[0], &n[1], &n[2]))
		for i := range toks {
			if n[i] > 0 {
				t.Errorf("%s is in %s.%s (%d rows)", names[i], c.table, c.column, n[i])
			}
		}
	}
}
