package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/svinson1121/vectorcore-mcx/internal/store"
)

type Store struct {
	db      *sql.DB
	dialect string
}

func Open(path string) (*Store, error) {
	return open("sqlite", path, "sqlite")
}

func OpenPostgres(dsn string) (*Store, error) {
	return open("pgx", dsn, "postgres")
}

func open(driver, dsn, dialect string) (*Store, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, dialect: dialect}
	if dialect == "sqlite" {
		if _, err := db.ExecContext(context.Background(), "PRAGMA foreign_keys=ON"); err != nil {
			db.Close()
			return nil, err
		}
		db.SetMaxOpenConns(1)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) q(query string) string {
	if s.dialect != "postgres" {
		return query
	}
	var b strings.Builder
	arg := 1
	for _, r := range query {
		if r == '?' {
			b.WriteString(fmt.Sprintf("$%d", arg))
			arg++
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	impi TEXT NOT NULL,
	impu TEXT NOT NULL,
	mcptt_id TEXT NOT NULL,
	display_name TEXT NOT NULL,
	enabled INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS groups (
	id TEXT PRIMARY KEY,
	uri TEXT NOT NULL UNIQUE,
	display_name TEXT NOT NULL,
	description TEXT NOT NULL,
	enabled INTEGER NOT NULL,
	multi_talker INTEGER NOT NULL DEFAULT 0,
	max_simultaneous_talkers INTEGER NOT NULL DEFAULT 0,
	chat_group INTEGER NOT NULL DEFAULT 0,
	allow_emergency_call INTEGER NOT NULL DEFAULT 0,
	max_duration_seconds INTEGER NOT NULL DEFAULT 0,
	is_default INTEGER NOT NULL DEFAULT 0, -- legacy/unused, kept to avoid a column-drop migration
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS affiliations (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	group_id TEXT NOT NULL,
	role TEXT NOT NULL,
	state TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS group_memberships (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	group_id TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'MCPTT User',
	priority INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(user_id, group_id),
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS group_affiliations (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	group_id TEXT NOT NULL,
	state TEXT NOT NULL,
	source TEXT NOT NULL DEFAULT '',
	expires_at TEXT NOT NULL DEFAULT '',
	last_publish_call_id TEXT NOT NULL DEFAULT '',
	last_seen_at TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(user_id, group_id),
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS cms_documents (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	auid TEXT NOT NULL,
	path TEXT NOT NULL,
	content_type TEXT NOT NULL,
	body TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS published_state (
	id TEXT PRIMARY KEY,
	user_uri TEXT NOT NULL,
	event TEXT NOT NULL,
	body TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(user_uri, event)
);
CREATE TABLE IF NOT EXISTS subscriptions (
	id TEXT PRIMARY KEY,
	call_id TEXT NOT NULL,
	event TEXT NOT NULL,
	subscriber_uri TEXT NOT NULL,
	target_uri TEXT NOT NULL,
	local_tag TEXT NOT NULL,
	remote_tag TEXT NOT NULL,
	route_set TEXT NOT NULL DEFAULT '',
	remote_target TEXT NOT NULL DEFAULT '',
	transport TEXT NOT NULL DEFAULT '',
	source_addr TEXT NOT NULL DEFAULT '',
	top_via TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dialogs (
	id TEXT PRIMARY KEY,
	call_id TEXT NOT NULL,
	local_tag TEXT NOT NULL,
	remote_tag TEXT NOT NULL,
	from_uri TEXT NOT NULL DEFAULT '',
	to_uri TEXT NOT NULL DEFAULT '',
	request_uri TEXT NOT NULL DEFAULT '',
	impu TEXT NOT NULL DEFAULT '',
	mcptt_id TEXT NOT NULL DEFAULT '',
	method TEXT NOT NULL,
	state TEXT NOT NULL,
	route_set TEXT NOT NULL,
	remote_target TEXT NOT NULL,
	record_route_used INTEGER NOT NULL DEFAULT 0,
	local_cseq INTEGER NOT NULL DEFAULT 0,
	remote_cseq INTEGER NOT NULL DEFAULT 0,
	last_method TEXT NOT NULL DEFAULT '',
	last_status INTEGER NOT NULL DEFAULT 0,
	transport TEXT NOT NULL DEFAULT '',
	source_addr TEXT NOT NULL DEFAULT '',
	top_via TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mcptt_registrations (
	id TEXT PRIMARY KEY,
	public_identity TEXT NOT NULL UNIQUE,
	imsi TEXT NOT NULL DEFAULT '',
	msisdn TEXT NOT NULL DEFAULT '',
	mcptt_id TEXT NOT NULL DEFAULT '',
	contact_uri TEXT NOT NULL DEFAULT '',
	contact_raw TEXT NOT NULL DEFAULT '',
	source_ip TEXT NOT NULL DEFAULT '',
	source_port INTEGER NOT NULL DEFAULT 0,
	transport TEXT NOT NULL DEFAULT '',
	call_id TEXT NOT NULL DEFAULT '',
	cseq TEXT NOT NULL DEFAULT '',
	registered INTEGER NOT NULL DEFAULT 0,
	state TEXT NOT NULL DEFAULT 'unknown',
	expires_at TEXT NOT NULL DEFAULT '',
	expires_seconds INTEGER NOT NULL DEFAULT 0,
	last_registered_at TEXT NOT NULL DEFAULT '',
	last_unregistered_at TEXT NOT NULL DEFAULT '',
	last_seen_at TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	feature_tags TEXT NOT NULL DEFAULT '[]',
	icsi_refs TEXT NOT NULL DEFAULT '[]',
	scscf_identity TEXT NOT NULL DEFAULT '',
	registration_source TEXT NOT NULL DEFAULT 'third_party_register'
);
CREATE TABLE IF NOT EXISTS mcptt_calls (
	id TEXT PRIMARY KEY,
	call_id TEXT NOT NULL UNIQUE,
	state TEXT NOT NULL,
	initiator_uri TEXT NOT NULL DEFAULT '',
	target_uri TEXT NOT NULL DEFAULT '',
	group_uri TEXT NOT NULL DEFAULT '',
	mcptt_id TEXT NOT NULL DEFAULT '',
	remote_target TEXT NOT NULL DEFAULT '',
	route_set TEXT NOT NULL DEFAULT '',
	local_tag TEXT NOT NULL DEFAULT '',
	remote_tag TEXT NOT NULL DEFAULT '',
	transport TEXT NOT NULL DEFAULT '',
	source_addr TEXT NOT NULL DEFAULT '',
	audio_ip TEXT NOT NULL DEFAULT '',
	audio_port INTEGER NOT NULL DEFAULT 0,
	audio_proto TEXT NOT NULL DEFAULT '',
	audio_payloads TEXT NOT NULL DEFAULT '[]',
	floor_control_ip TEXT NOT NULL DEFAULT '',
	floor_control_port INTEGER NOT NULL DEFAULT 0,
	floor_control_proto TEXT NOT NULL DEFAULT '',
	floor_control_payloads TEXT NOT NULL DEFAULT '[]',
	media_attributes TEXT NOT NULL DEFAULT '[]',
	floor_control_attrs TEXT NOT NULL DEFAULT '[]',
	local_audio_port INTEGER NOT NULL DEFAULT 0,
	local_rtcp_port INTEGER NOT NULL DEFAULT 0,
	local_floor_port INTEGER NOT NULL DEFAULT 0,
	rtp_packets INTEGER NOT NULL DEFAULT 0,
	rtp_bytes INTEGER NOT NULL DEFAULT 0,
	rtp_rejected_packets INTEGER NOT NULL DEFAULT 0,
	rtp_rejected_bytes INTEGER NOT NULL DEFAULT 0,
	rtp_payload_type INTEGER NOT NULL DEFAULT 0,
	rtp_ssrc INTEGER NOT NULL DEFAULT 0,
	rtp_first_sequence INTEGER NOT NULL DEFAULT 0,
	rtp_last_sequence INTEGER NOT NULL DEFAULT 0,
	rtp_last_timestamp INTEGER NOT NULL DEFAULT 0,
	rtp_sequence_cycles INTEGER NOT NULL DEFAULT 0,
	rtp_expected_packets INTEGER NOT NULL DEFAULT 0,
	rtp_lost_packets INTEGER NOT NULL DEFAULT 0,
	rtp_jitter REAL NOT NULL DEFAULT 0,
	rtcp_packets INTEGER NOT NULL DEFAULT 0,
	rtcp_bytes INTEGER NOT NULL DEFAULT 0,
	floor_packets INTEGER NOT NULL DEFAULT 0,
	floor_bytes INTEGER NOT NULL DEFAULT 0,
	floor_state TEXT NOT NULL DEFAULT '',
	floor_last_event TEXT NOT NULL DEFAULT '',
	floor_last_subtype INTEGER NOT NULL DEFAULT 0,
	floor_ssrc INTEGER NOT NULL DEFAULT 0,
	floor_holder TEXT NOT NULL DEFAULT '',
	floor_granted_at TEXT NOT NULL DEFAULT '',
	floor_released_at TEXT NOT NULL DEFAULT '',
	floor_updated_at TEXT NOT NULL DEFAULT '',
	last_rtp_at TEXT NOT NULL DEFAULT '',
	last_rtcp_at TEXT NOT NULL DEFAULT '',
	last_floor_at TEXT NOT NULL DEFAULT '',
	sdp_offer TEXT NOT NULL DEFAULT '',
	sdp_answer TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	answered_at TEXT NOT NULL DEFAULT '',
	established_at TEXT NOT NULL DEFAULT '',
	session_expires_at TEXT NOT NULL DEFAULT '',
	terminated_at TEXT NOT NULL DEFAULT ''
);`)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS functional_aliases (
	id TEXT PRIMARY KEY,
	mcptt_id TEXT NOT NULL,
	alias_uri TEXT NOT NULL,
	status TEXT NOT NULL,
	p_id_fa TEXT NOT NULL DEFAULT '',
	expires_at TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	UNIQUE(mcptt_id, alias_uri)
);
CREATE TABLE IF NOT EXISTS ue_contacts (
	ue_ip   TEXT PRIMARY KEY,
	mcptt_id TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL DEFAULT ''
);`)
	if err != nil {
		return err
	}
	if s.dialect == "postgres" {
		if _, err := s.db.ExecContext(ctx, `
INSERT INTO group_memberships (id, user_id, group_id, role, priority, created_at, updated_at)
SELECT id, user_id, group_id, CASE LOWER(TRIM(COALESCE(NULLIF(role, ''), 'MCPTT User')))
  WHEN 'member' THEN 'MCPTT User'
  WHEN 'user' THEN 'MCPTT User'
  WHEN 'admin' THEN 'MCPTT Administrator'
  WHEN 'administrator' THEN 'MCPTT Administrator'
  WHEN 'dispatcher' THEN 'MCPTT Dispatcher'
  WHEN 'supervisor' THEN 'MCPTT Supervisor'
  ELSE COALESCE(NULLIF(role, ''), 'MCPTT User')
END, 0, created_at, updated_at
FROM affiliations
ON CONFLICT (user_id, group_id) DO NOTHING;
`); err != nil {
			return err
		}
	} else {
		if _, err := s.db.ExecContext(ctx, `
INSERT OR IGNORE INTO group_memberships (id, user_id, group_id, role, priority, created_at, updated_at)
SELECT id, user_id, group_id, CASE LOWER(TRIM(COALESCE(NULLIF(role, ''), 'MCPTT User')))
  WHEN 'member' THEN 'MCPTT User'
  WHEN 'user' THEN 'MCPTT User'
  WHEN 'admin' THEN 'MCPTT Administrator'
  WHEN 'administrator' THEN 'MCPTT Administrator'
  WHEN 'dispatcher' THEN 'MCPTT Dispatcher'
  WHEN 'supervisor' THEN 'MCPTT Supervisor'
  ELSE COALESCE(NULLIF(role, ''), 'MCPTT User')
END, 0, created_at, updated_at
FROM affiliations;
`); err != nil {
			return err
		}
	}
	for _, stmt := range []string{
		`ALTER TABLE users ADD COLUMN functional_aliases TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE groups ADD COLUMN is_default INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE groups ADD COLUMN multi_talker INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE groups ADD COLUMN max_simultaneous_talkers INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE groups ADD COLUMN chat_group INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE groups ADD COLUMN allow_emergency_call INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN allow_emergency_call INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN session_expires_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE groups ADD COLUMN max_duration_seconds INTEGER NOT NULL DEFAULT 0`,
		`UPDATE group_memberships SET role = 'MCPTT User' WHERE LOWER(TRIM(role)) IN ('', 'member', 'user')`,
		`UPDATE group_memberships SET role = 'MCPTT Administrator' WHERE LOWER(TRIM(role)) IN ('admin', 'administrator')`,
		`UPDATE group_memberships SET role = 'MCPTT Dispatcher' WHERE LOWER(TRIM(role)) = 'dispatcher'`,
		`UPDATE group_memberships SET role = 'MCPTT Supervisor' WHERE LOWER(TRIM(role)) = 'supervisor'`,
		`ALTER TABLE subscriptions ADD COLUMN route_set TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE subscriptions ADD COLUMN remote_target TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE subscriptions ADD COLUMN transport TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE subscriptions ADD COLUMN source_addr TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE subscriptions ADD COLUMN top_via TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE dialogs ADD COLUMN transport TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE dialogs ADD COLUMN source_addr TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE dialogs ADD COLUMN top_via TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE dialogs ADD COLUMN from_uri TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE dialogs ADD COLUMN to_uri TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE dialogs ADD COLUMN request_uri TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE dialogs ADD COLUMN impu TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE dialogs ADD COLUMN mcptt_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE dialogs ADD COLUMN record_route_used INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE dialogs ADD COLUMN local_cseq INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE dialogs ADD COLUMN remote_cseq INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE dialogs ADD COLUMN last_method TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE dialogs ADD COLUMN last_status INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN audio_ip TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN audio_port INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN audio_proto TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN audio_payloads TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_control_ip TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_control_port INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_control_proto TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_control_payloads TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE mcptt_calls ADD COLUMN media_attributes TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_control_attrs TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE mcptt_calls ADD COLUMN local_audio_port INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN local_rtcp_port INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN local_floor_port INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_packets INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_bytes INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_rejected_packets INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_rejected_bytes INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_payload_type INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_ssrc INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_first_sequence INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_last_sequence INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_last_timestamp INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_sequence_cycles INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_expected_packets INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_lost_packets INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtp_jitter REAL NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtcp_packets INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN rtcp_bytes INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_packets INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_bytes INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_state TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_last_event TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_last_subtype INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_ssrc INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_holder TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_granted_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_released_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN floor_updated_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN last_rtp_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN last_rtcp_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mcptt_calls ADD COLUMN last_floor_at TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") && !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}
	if err := s.createIndexes(ctx); err != nil {
		return err
	}
	return s.normaliseTimestamps(ctx)
}

// createIndexes adds the indexes the hot paths need. The schema previously had
// none at all beyond the implicit ones behind UNIQUE constraints, so lookups
// that run per media packet were full table scans.
//
// CREATE INDEX IF NOT EXISTS is understood by both SQLite and PostgreSQL, so
// these need no dialect branch.
func (s *Store) createIndexes(ctx context.Context) error {
	indexes := []string{
		// matchCall and relayRTP run these for every RTP, RTCP and floor
		// packet, against a table whose rows carry ~60 columns.
		`CREATE INDEX IF NOT EXISTS idx_mcptt_calls_group_uri ON mcptt_calls (group_uri)`,
		`CREATE INDEX IF NOT EXISTS idx_mcptt_calls_audio_ip ON mcptt_calls (audio_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_mcptt_calls_updated_at ON mcptt_calls (updated_at)`,

		// Dialog and subscription lookup by Call-ID on every in-dialog request.
		`CREATE INDEX IF NOT EXISTS idx_dialogs_call_id ON dialogs (call_id)`,
		`CREATE INDEX IF NOT EXISTS idx_subscriptions_call_id ON subscriptions (call_id)`,

		// The membership and affiliation pairs are unique on (user_id,
		// group_id), which cannot serve a lookup by group alone.
		`CREATE INDEX IF NOT EXISTS idx_group_memberships_group_id ON group_memberships (group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_group_affiliations_group_id ON group_affiliations (group_id)`,

		// Expiry sweeps, which run every ten seconds.
		`CREATE INDEX IF NOT EXISTS idx_group_affiliations_expires_at ON group_affiliations (expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_mcptt_registrations_expires_at ON mcptt_registrations (expires_at)`,

		// XCAP documents are addressed by path on every CMS request.
		`CREATE INDEX IF NOT EXISTS idx_cms_documents_path ON cms_documents (path)`,
	}

	for _, stmt := range indexes {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create index: %w", err)
		}
	}
	return nil
}

// orderedTimestampColumns are the TEXT timestamp columns that SQL compares or
// orders directly, so their textual width has to be uniform. Columns that are
// only read back into Go are not listed: parseTime accepts either width.
var orderedTimestampColumns = map[string][]string{
	"group_affiliations":  {"expires_at", "last_seen_at", "updated_at"},
	"group_memberships":   {"updated_at"},
	"mcptt_registrations": {"expires_at", "last_seen_at", "updated_at"},
	"mcptt_calls":         {"updated_at"},
	"dialogs":             {"updated_at"},
}

// normaliseTimestamps rewrites timestamps written by earlier versions, which
// used time.RFC3339Nano and so produced a variable-width fractional second, to
// the fixed-width layout. Without this, rows written before and after the
// change compare incorrectly against each other.
//
// Rows already in the canonical form are left untouched, so this settles after
// the first run.
func (s *Store) normaliseTimestamps(ctx context.Context) error {
	for table, columns := range orderedTimestampColumns {
		for _, column := range columns {
			if err := s.normaliseTimestampColumn(ctx, table, column); err != nil {
				return fmt.Errorf("normalise %s.%s: %w", table, column, err)
			}
		}
	}
	return nil
}

func (s *Store) normaliseTimestampColumn(ctx context.Context, table, column string) error {
	// table and column come from the map above, never from user input.
	query := fmt.Sprintf("SELECT id, %s FROM %s WHERE %s != ''", column, table, column)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		// The table may not exist yet on a fresh database.
		return nil //nolint:nilerr // absent table is not an error here
	}

	type fix struct{ id, value string }
	var fixes []fix
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		t := parseTime(raw)
		if t.IsZero() {
			continue
		}
		if canonical := formatTime(t); canonical != raw {
			fixes = append(fixes, fix{id: id, value: canonical})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	if len(fixes) == 0 {
		return nil
	}
	update := s.q(fmt.Sprintf("UPDATE %s SET %s = ? WHERE id = ?", table, column))
	for _, f := range fixes {
		if _, err := s.db.ExecContext(ctx, update, f.value, f.id); err != nil {
			return err
		}
	}
	slog.Info("normalised legacy timestamps", "table", table, "column", column, "rows", len(fixes))
	return nil
}

func stampNew(id string) (string, time.Time, time.Time) {
	now := time.Now().UTC()
	if id == "" {
		id = uuid.NewString()
	}
	return id, now, now
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func scanBool(v int) bool { return v != 0 }

func parseTime(v string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, v)
	return t
}

// timestampLayout is RFC 3339 with a fixed nine-digit fractional second.
//
// time.RFC3339Nano strips trailing zeros, so its output has variable width and
// cannot be compared as text: ".5Z" sorts after ".55Z", because 'Z' (0x5A) is
// greater than '5' (0x35), even though 0.5 precedes 0.55. Every timestamp
// column here is TEXT, and several are compared or ordered directly in SQL, so
// the width has to be constant.
const timestampLayout = "2006-01-02T15:04:05.000000000Z07:00"

func formatTime(v time.Time) string {
	if v.IsZero() {
		return ""
	}
	return v.UTC().Format(timestampLayout)
}

func marshalStrings(v []string) string {
	if v == nil {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func unmarshalStrings(v string) []string {
	var out []string
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil
	}
	return out
}

func notFound(err error) (bool, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	return false, err
}

func (s *Store) ListUsers(ctx context.Context) ([]store.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, impi, impu, mcptt_id, display_name, enabled, functional_aliases, allow_emergency_call, created_at, updated_at FROM users ORDER BY display_name, mcptt_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.User
	for rows.Next() {
		var v store.User
		var enabled, allowEmergency int
		var aliases, created, updated string
		if err := rows.Scan(&v.ID, &v.IMPI, &v.IMPU, &v.MCPTTID, &v.DisplayName, &enabled, &aliases, &allowEmergency, &created, &updated); err != nil {
			return nil, err
		}
		v.Enabled = scanBool(enabled)
		v.AllowEmergencyCall = scanBool(allowEmergency)
		v.FunctionalAliases = unmarshalStrings(aliases)
		v.CreatedAt = parseTime(created)
		v.UpdatedAt = parseTime(updated)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetUser(ctx context.Context, id string) (*store.User, error) {
	var v store.User
	var enabled, allowEmergency int
	var aliases, created, updated string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id, impi, impu, mcptt_id, display_name, enabled, functional_aliases, allow_emergency_call, created_at, updated_at FROM users WHERE id = ?`), id).
		Scan(&v.ID, &v.IMPI, &v.IMPU, &v.MCPTTID, &v.DisplayName, &enabled, &aliases, &allowEmergency, &created, &updated)
	if ok, err := notFound(err); ok || err != nil {
		return nil, err
	}
	v.Enabled = scanBool(enabled)
	v.AllowEmergencyCall = scanBool(allowEmergency)
	v.FunctionalAliases = unmarshalStrings(aliases)
	v.CreatedAt = parseTime(created)
	v.UpdatedAt = parseTime(updated)
	return &v, nil
}

// UpsertFunctionalAliasStatus stores one functional alias information entry
// (TS 24.379 clause 9A.2.2.2.2), keyed on (MCPTT ID, alias).
func (s *Store) UpsertFunctionalAliasStatus(ctx context.Context, v store.FunctionalAliasStatus) (store.FunctionalAliasStatus, error) {
	now := time.Now().UTC()
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	v.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO functional_aliases (id, mcptt_id, alias_uri, status, p_id_fa, expires_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(mcptt_id, alias_uri) DO UPDATE SET status=excluded.status, p_id_fa=excluded.p_id_fa, expires_at=excluded.expires_at, updated_at=excluded.updated_at`),
		v.ID, v.MCPTTID, v.AliasURI, v.Status, v.PIDFA, formatTime(v.ExpiresAt), formatTime(v.UpdatedAt))
	return v, err
}

// ListFunctionalAliasStatuses returns the functional alias entries of one
// MCPTT user.
func (s *Store) ListFunctionalAliasStatuses(ctx context.Context, mcpttID string) ([]store.FunctionalAliasStatus, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, mcptt_id, alias_uri, status, p_id_fa, expires_at, updated_at
FROM functional_aliases WHERE mcptt_id = ? ORDER BY alias_uri`), mcpttID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.FunctionalAliasStatus
	for rows.Next() {
		var v store.FunctionalAliasStatus
		var expires, updated string
		if err := rows.Scan(&v.ID, &v.MCPTTID, &v.AliasURI, &v.Status, &v.PIDFA, &expires, &updated); err != nil {
			return nil, err
		}
		v.ExpiresAt = parseTime(expires)
		v.UpdatedAt = parseTime(updated)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, v store.User) (store.User, error) {
	v.ID, v.CreatedAt, v.UpdatedAt = stampNew(v.ID)
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO users (id, impi, impu, mcptt_id, display_name, enabled, functional_aliases, allow_emergency_call, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		v.ID, v.IMPI, v.IMPU, v.MCPTTID, v.DisplayName, boolInt(v.Enabled), marshalStrings(v.FunctionalAliases), boolInt(v.AllowEmergencyCall), formatTime(v.CreatedAt), formatTime(v.UpdatedAt))
	return v, err
}

func (s *Store) UpdateUser(ctx context.Context, id string, v store.User) (*store.User, error) {
	current, err := s.GetUser(ctx, id)
	if err != nil || current == nil {
		return current, err
	}
	v.ID = id
	v.CreatedAt = current.CreatedAt
	v.UpdatedAt = time.Now().UTC()
	_, err = s.db.ExecContext(ctx, s.q(`UPDATE users SET impi=?, impu=?, mcptt_id=?, display_name=?, enabled=?, functional_aliases=?, allow_emergency_call=?, updated_at=? WHERE id=?`),
		v.IMPI, v.IMPU, v.MCPTTID, v.DisplayName, boolInt(v.Enabled), marshalStrings(v.FunctionalAliases), boolInt(v.AllowEmergencyCall), formatTime(v.UpdatedAt), id)
	return &v, err
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM users WHERE id = ?`), id)
	return err
}

func (s *Store) ListGroups(ctx context.Context) ([]store.Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, uri, display_name, description, enabled, multi_talker, max_simultaneous_talkers, chat_group, allow_emergency_call, max_duration_seconds, created_at, updated_at FROM groups ORDER BY display_name, uri`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Group
	for rows.Next() {
		var v store.Group
		var enabled, multiTalker, chatGroup, allowEmergency int
		var created, updated string
		if err := rows.Scan(&v.ID, &v.URI, &v.DisplayName, &v.Description, &enabled, &multiTalker, &v.MaxSimultaneousTalkers, &chatGroup, &allowEmergency, &v.MaxDurationSeconds, &created, &updated); err != nil {
			return nil, err
		}
		v.Enabled = scanBool(enabled)
		v.MultiTalker = scanBool(multiTalker)
		v.ChatGroup = scanBool(chatGroup)
		v.AllowEmergencyCall = scanBool(allowEmergency)
		v.CreatedAt = parseTime(created)
		v.UpdatedAt = parseTime(updated)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetGroup(ctx context.Context, id string) (*store.Group, error) {
	var v store.Group
	var enabled, multiTalker, chatGroup, allowEmergency int
	var created, updated string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id, uri, display_name, description, enabled, multi_talker, max_simultaneous_talkers, chat_group, allow_emergency_call, max_duration_seconds, created_at, updated_at FROM groups WHERE id = ?`), id).
		Scan(&v.ID, &v.URI, &v.DisplayName, &v.Description, &enabled, &multiTalker, &v.MaxSimultaneousTalkers, &chatGroup, &allowEmergency, &v.MaxDurationSeconds, &created, &updated)
	if ok, err := notFound(err); ok || err != nil {
		return nil, err
	}
	v.Enabled = scanBool(enabled)
	v.MultiTalker = scanBool(multiTalker)
	v.ChatGroup = scanBool(chatGroup)
	v.AllowEmergencyCall = scanBool(allowEmergency)
	v.CreatedAt = parseTime(created)
	v.UpdatedAt = parseTime(updated)
	return &v, nil
}

func (s *Store) CreateGroup(ctx context.Context, v store.Group) (store.Group, error) {
	v.ID, v.CreatedAt, v.UpdatedAt = stampNew(v.ID)
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO groups (id, uri, display_name, description, enabled, multi_talker, max_simultaneous_talkers, chat_group, allow_emergency_call, max_duration_seconds, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		v.ID, v.URI, v.DisplayName, v.Description, boolInt(v.Enabled), boolInt(v.MultiTalker), v.MaxSimultaneousTalkers, boolInt(v.ChatGroup), boolInt(v.AllowEmergencyCall), v.MaxDurationSeconds, formatTime(v.CreatedAt), formatTime(v.UpdatedAt))
	return v, err
}

func (s *Store) UpdateGroup(ctx context.Context, id string, v store.Group) (*store.Group, error) {
	current, err := s.GetGroup(ctx, id)
	if err != nil || current == nil {
		return current, err
	}
	v.ID = id
	v.CreatedAt = current.CreatedAt
	v.UpdatedAt = time.Now().UTC()
	_, err = s.db.ExecContext(ctx, s.q(`UPDATE groups SET uri=?, display_name=?, description=?, enabled=?, multi_talker=?, max_simultaneous_talkers=?, chat_group=?, allow_emergency_call=?, max_duration_seconds=?, updated_at=? WHERE id=?`),
		v.URI, v.DisplayName, v.Description, boolInt(v.Enabled), boolInt(v.MultiTalker), v.MaxSimultaneousTalkers, boolInt(v.ChatGroup), boolInt(v.AllowEmergencyCall), v.MaxDurationSeconds, formatTime(v.UpdatedAt), id)
	return &v, err
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM groups WHERE id = ?`), id)
	return err
}

func (s *Store) ListGroupMemberships(ctx context.Context) ([]store.GroupMembership, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, group_id, role, priority, created_at, updated_at FROM group_memberships ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.GroupMembership
	for rows.Next() {
		var v store.GroupMembership
		var created, updated string
		if err := rows.Scan(&v.ID, &v.UserID, &v.GroupID, &v.Role, &v.Priority, &created, &updated); err != nil {
			return nil, err
		}
		v.CreatedAt = parseTime(created)
		v.UpdatedAt = parseTime(updated)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetGroupMembership(ctx context.Context, id string) (*store.GroupMembership, error) {
	var v store.GroupMembership
	var created, updated string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id, user_id, group_id, role, priority, created_at, updated_at FROM group_memberships WHERE id = ?`), id).
		Scan(&v.ID, &v.UserID, &v.GroupID, &v.Role, &v.Priority, &created, &updated)
	if ok, err := notFound(err); ok || err != nil {
		return nil, err
	}
	v.CreatedAt = parseTime(created)
	v.UpdatedAt = parseTime(updated)
	return &v, nil
}

func (s *Store) CreateGroupMembership(ctx context.Context, v store.GroupMembership) (store.GroupMembership, error) {
	v.ID, v.CreatedAt, v.UpdatedAt = stampNew(v.ID)
	role, err := mcpttParticipantTypeValue(v.Role)
	if err != nil {
		return v, err
	}
	v.Role = role
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO group_memberships (id, user_id, group_id, role, priority, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		v.ID, v.UserID, v.GroupID, v.Role, v.Priority, formatTime(v.CreatedAt), formatTime(v.UpdatedAt))
	return v, err
}

func (s *Store) UpdateGroupMembership(ctx context.Context, id string, v store.GroupMembership) (*store.GroupMembership, error) {
	current, err := s.GetGroupMembership(ctx, id)
	if err != nil || current == nil {
		return current, err
	}
	v.ID = id
	v.CreatedAt = current.CreatedAt
	v.UpdatedAt = time.Now().UTC()
	role, err := mcpttParticipantTypeValue(v.Role)
	if err != nil {
		return nil, err
	}
	v.Role = role
	_, err = s.db.ExecContext(ctx, s.q(`UPDATE group_memberships SET user_id=?, group_id=?, role=?, priority=?, updated_at=? WHERE id=?`),
		v.UserID, v.GroupID, v.Role, v.Priority, formatTime(v.UpdatedAt), id)
	return &v, err
}

func (s *Store) DeleteGroupMembership(ctx context.Context, id string) error {
	m, err := s.GetGroupMembership(ctx, id)
	if err != nil || m == nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, s.q(`DELETE FROM group_affiliations WHERE user_id = ? AND group_id = ?`), m.UserID, m.GroupID); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.q(`DELETE FROM group_memberships WHERE id = ?`), id)
	return err
}

func mcpttParticipantTypeValue(role string) (string, error) {
	role = strings.TrimSpace(role)
	if role == "" {
		return "MCPTT User", nil
	}
	switch role {
	case "MCPTT User", "MCPTT Administrator", "MCPTT Dispatcher", "MCPTT Supervisor":
		return role, nil
	default:
		return "", fmt.Errorf("unsupported MCPTT participant type %q", role)
	}
}

func (s *Store) IsGroupMember(ctx context.Context, userID, groupID string) (bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id FROM group_memberships WHERE user_id = ? AND group_id = ? LIMIT 1`), userID, groupID).Scan(&id)
	if ok, err := notFound(err); ok || err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ListGroupAffiliations(ctx context.Context) ([]store.GroupAffiliation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, group_id, state, source, expires_at, last_publish_call_id, last_seen_at, created_at, updated_at FROM group_affiliations ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.GroupAffiliation
	for rows.Next() {
		var v store.GroupAffiliation
		var expires, lastSeen, created, updated string
		if err := rows.Scan(&v.ID, &v.UserID, &v.GroupID, &v.State, &v.Source, &expires, &v.LastPublishCallID, &lastSeen, &created, &updated); err != nil {
			return nil, err
		}
		v.ExpiresAt = parseTime(expires)
		v.LastSeenAt = parseTime(lastSeen)
		v.CreatedAt = parseTime(created)
		v.UpdatedAt = parseTime(updated)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetGroupAffiliation(ctx context.Context, id string) (*store.GroupAffiliation, error) {
	var v store.GroupAffiliation
	var expires, lastSeen, created, updated string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id, user_id, group_id, state, source, expires_at, last_publish_call_id, last_seen_at, created_at, updated_at FROM group_affiliations WHERE id = ?`), id).
		Scan(&v.ID, &v.UserID, &v.GroupID, &v.State, &v.Source, &expires, &v.LastPublishCallID, &lastSeen, &created, &updated)
	if ok, err := notFound(err); ok || err != nil {
		return nil, err
	}
	v.ExpiresAt = parseTime(expires)
	v.LastSeenAt = parseTime(lastSeen)
	v.CreatedAt = parseTime(created)
	v.UpdatedAt = parseTime(updated)
	return &v, nil
}

func (s *Store) CreateGroupAffiliation(ctx context.Context, v store.GroupAffiliation) (store.GroupAffiliation, error) {
	member, err := s.IsGroupMember(ctx, v.UserID, v.GroupID)
	if err != nil {
		return v, err
	}
	if !member {
		return v, fmt.Errorf("user %s is not a member of group %s", v.UserID, v.GroupID)
	}
	v.ID, v.CreatedAt, v.UpdatedAt = stampNew(v.ID)
	if v.State == "" {
		v.State = "affiliated"
	}
	if v.LastSeenAt.IsZero() {
		v.LastSeenAt = v.UpdatedAt
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO group_affiliations (id, user_id, group_id, state, source, expires_at, last_publish_call_id, last_seen_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		v.ID, v.UserID, v.GroupID, v.State, v.Source, formatTime(v.ExpiresAt), v.LastPublishCallID, formatTime(v.LastSeenAt), formatTime(v.CreatedAt), formatTime(v.UpdatedAt))
	return v, err
}

func (s *Store) UpdateGroupAffiliation(ctx context.Context, id string, v store.GroupAffiliation) (*store.GroupAffiliation, error) {
	current, err := s.GetGroupAffiliation(ctx, id)
	if err != nil || current == nil {
		return current, err
	}
	member, err := s.IsGroupMember(ctx, v.UserID, v.GroupID)
	if err != nil {
		return nil, err
	}
	if !member {
		return nil, fmt.Errorf("user %s is not a member of group %s", v.UserID, v.GroupID)
	}
	v.ID = id
	v.CreatedAt = current.CreatedAt
	v.UpdatedAt = time.Now().UTC()
	if v.State == "" {
		v.State = current.State
	}
	if v.LastSeenAt.IsZero() {
		v.LastSeenAt = v.UpdatedAt
	}
	_, err = s.db.ExecContext(ctx, s.q(`UPDATE group_affiliations SET user_id=?, group_id=?, state=?, source=?, expires_at=?, last_publish_call_id=?, last_seen_at=?, updated_at=? WHERE id=?`),
		v.UserID, v.GroupID, v.State, v.Source, formatTime(v.ExpiresAt), v.LastPublishCallID, formatTime(v.LastSeenAt), formatTime(v.UpdatedAt), id)
	return &v, err
}

func (s *Store) DeleteGroupAffiliation(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM group_affiliations WHERE id = ?`), id)
	return err
}

func (s *Store) IsGroupAffiliated(ctx context.Context, userID, groupID string) (bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id FROM group_affiliations WHERE user_id = ? AND group_id = ? AND state = 'affiliated' AND (expires_at = '' OR expires_at > ?) LIMIT 1`),
		userID, groupID, formatTime(time.Now().UTC())).Scan(&id)
	if ok, err := notFound(err); ok || err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ListCMSDocuments(ctx context.Context) ([]store.CMSDocument, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, auid, path, content_type, body, created_at, updated_at FROM cms_documents ORDER BY name, path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CMSDocument
	for rows.Next() {
		var v store.CMSDocument
		var created, updated string
		if err := rows.Scan(&v.ID, &v.Name, &v.AUID, &v.Path, &v.ContentType, &v.Body, &created, &updated); err != nil {
			return nil, err
		}
		v.CreatedAt = parseTime(created)
		v.UpdatedAt = parseTime(updated)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetCMSDocument(ctx context.Context, id string) (*store.CMSDocument, error) {
	var v store.CMSDocument
	var created, updated string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id, name, auid, path, content_type, body, created_at, updated_at FROM cms_documents WHERE id = ?`), id).
		Scan(&v.ID, &v.Name, &v.AUID, &v.Path, &v.ContentType, &v.Body, &created, &updated)
	if ok, err := notFound(err); ok || err != nil {
		return nil, err
	}
	v.CreatedAt = parseTime(created)
	v.UpdatedAt = parseTime(updated)
	return &v, nil
}

func (s *Store) GetCMSDocumentByPath(ctx context.Context, path string) (*store.CMSDocument, error) {
	var v store.CMSDocument
	var created, updated string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id, name, auid, path, content_type, body, created_at, updated_at FROM cms_documents WHERE path = ?`), path).
		Scan(&v.ID, &v.Name, &v.AUID, &v.Path, &v.ContentType, &v.Body, &created, &updated)
	if ok, err := notFound(err); ok || err != nil {
		return nil, err
	}
	v.CreatedAt = parseTime(created)
	v.UpdatedAt = parseTime(updated)
	return &v, nil
}

func (s *Store) CreateCMSDocument(ctx context.Context, v store.CMSDocument) (store.CMSDocument, error) {
	v.ID, v.CreatedAt, v.UpdatedAt = stampNew(v.ID)
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO cms_documents (id, name, auid, path, content_type, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		v.ID, v.Name, v.AUID, v.Path, v.ContentType, v.Body, formatTime(v.CreatedAt), formatTime(v.UpdatedAt))
	return v, err
}

func (s *Store) UpdateCMSDocument(ctx context.Context, id string, v store.CMSDocument) (*store.CMSDocument, error) {
	current, err := s.GetCMSDocument(ctx, id)
	if err != nil || current == nil {
		return current, err
	}
	v.ID = id
	v.CreatedAt = current.CreatedAt
	v.UpdatedAt = time.Now().UTC()
	_, err = s.db.ExecContext(ctx, s.q(`UPDATE cms_documents SET name=?, auid=?, path=?, content_type=?, body=?, updated_at=? WHERE id=?`),
		v.Name, v.AUID, v.Path, v.ContentType, v.Body, formatTime(v.UpdatedAt), id)
	return &v, err
}

func (s *Store) DeleteCMSDocument(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM cms_documents WHERE id = ?`), id)
	return err
}

func (s *Store) UpsertPublishedState(ctx context.Context, v store.PublishedState) (store.PublishedState, error) {
	now := time.Now().UTC()
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	v.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO published_state (id, user_uri, event, body, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(user_uri, event) DO UPDATE SET body=excluded.body, updated_at=excluded.updated_at`),
		v.ID, v.UserURI, v.Event, v.Body, formatTime(v.UpdatedAt))
	return v, err
}

// GetPublishedState returns the stored PUBLISH state for a user and event
// package, or nil when the user has never published it.
func (s *Store) GetPublishedState(ctx context.Context, userURI, event string) (*store.PublishedState, error) {
	var v store.PublishedState
	var updated string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id, user_uri, event, body, updated_at
FROM published_state WHERE user_uri = ? AND event = ?`), userURI, event).
		Scan(&v.ID, &v.UserURI, &v.Event, &v.Body, &updated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v.UpdatedAt = parseTime(updated)
	return &v, nil
}

func (s *Store) CreateSubscription(ctx context.Context, v store.Subscription) (store.Subscription, error) {
	v.ID, v.CreatedAt, _ = stampNew(v.ID)
	if v.ExpiresAt.IsZero() {
		v.ExpiresAt = v.CreatedAt.Add(time.Hour)
	}
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO subscriptions (id, call_id, event, subscriber_uri, target_uri, local_tag, remote_tag, route_set, remote_target, transport, source_addr, top_via, state, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		v.ID, v.CallID, v.Event, v.SubscriberURI, v.TargetURI, v.LocalTag, v.RemoteTag,
		v.RouteSet, v.RemoteTarget, v.Transport, v.SourceAddr, v.TopVia, v.State,
		formatTime(v.ExpiresAt), formatTime(v.CreatedAt))
	return v, err
}

func (s *Store) CreateDialog(ctx context.Context, v store.Dialog) (store.Dialog, error) {
	v.ID, v.CreatedAt, v.UpdatedAt = stampNew(v.ID)
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO dialogs (
id, call_id, local_tag, remote_tag, from_uri, to_uri, request_uri, impu, mcptt_id, method, state,
route_set, remote_target, record_route_used, local_cseq, remote_cseq, last_method, last_status,
transport, source_addr, top_via, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		v.ID, v.CallID, v.LocalTag, v.RemoteTag, v.FromURI, v.ToURI, v.RequestURI, v.IMPU, v.MCPTTID, v.Method, v.State,
		v.RouteSet, v.RemoteTarget, boolInt(v.RecordRouteUsed), v.LocalCSeq, v.RemoteCSeq, v.LastMethod, v.LastStatus,
		v.Transport, v.SourceAddr, v.TopVia,
		formatTime(v.CreatedAt), formatTime(v.UpdatedAt))
	return v, err
}

func (s *Store) UpdateDialogState(ctx context.Context, callID, state string) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE dialogs SET state = ?, updated_at = ? WHERE call_id = ?`),
		state, formatTime(time.Now().UTC()), callID)
	return err
}

func (s *Store) FindDialog(ctx context.Context, callID, fromTag, toTag string) (*store.Dialog, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT id, call_id, local_tag, remote_tag, from_uri, to_uri, request_uri,
impu, mcptt_id, method, state, route_set, remote_target, record_route_used, local_cseq, remote_cseq,
last_method, last_status, transport, source_addr, top_via, created_at, updated_at
FROM dialogs WHERE call_id = ? AND ((local_tag = ? AND remote_tag = ?) OR (local_tag = ? AND remote_tag = ?))
ORDER BY updated_at DESC LIMIT 1`), callID, toTag, fromTag, fromTag, toTag)
	v, err := scanDialog(row)
	if ok, err := notFound(err); ok || err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Store) ListDialogs(ctx context.Context) ([]store.Dialog, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, call_id, local_tag, remote_tag, from_uri, to_uri, request_uri,
impu, mcptt_id, method, state, route_set, remote_target, record_route_used, local_cseq, remote_cseq,
last_method, last_status, transport, source_addr, top_via, created_at, updated_at
FROM dialogs ORDER BY updated_at DESC, call_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Dialog
	for rows.Next() {
		v, err := scanDialog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) UpsertCall(ctx context.Context, v store.MCPTTCall) (store.MCPTTCall, error) {
	now := time.Now().UTC()
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = now
	}
	v.UpdatedAt = now
	if v.State == "" {
		v.State = "invited"
	}
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO mcptt_calls (
id, call_id, state, initiator_uri, target_uri, group_uri, mcptt_id, remote_target, route_set,
local_tag, remote_tag, transport, source_addr, audio_ip, audio_port, audio_proto, audio_payloads,
floor_control_ip, floor_control_port, floor_control_proto, floor_control_payloads, media_attributes,
floor_control_attrs, local_audio_port, local_rtcp_port, local_floor_port, rtp_packets, rtp_bytes,
rtp_rejected_packets, rtp_rejected_bytes, rtp_payload_type, rtp_ssrc, rtp_first_sequence, rtp_last_sequence, rtp_last_timestamp, rtp_sequence_cycles,
rtp_expected_packets, rtp_lost_packets, rtp_jitter, rtcp_packets, rtcp_bytes, floor_packets, floor_bytes, last_rtp_at, last_rtcp_at, last_floor_at,
sdp_offer, sdp_answer, created_at, updated_at, answered_at, established_at,
terminated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(call_id) DO UPDATE SET
state=excluded.state,
initiator_uri=CASE WHEN excluded.initiator_uri != '' THEN excluded.initiator_uri ELSE mcptt_calls.initiator_uri END,
target_uri=CASE WHEN excluded.target_uri != '' THEN excluded.target_uri ELSE mcptt_calls.target_uri END,
group_uri=CASE WHEN excluded.group_uri != '' THEN excluded.group_uri ELSE mcptt_calls.group_uri END,
mcptt_id=CASE WHEN excluded.mcptt_id != '' THEN excluded.mcptt_id ELSE mcptt_calls.mcptt_id END,
remote_target=CASE WHEN excluded.remote_target != '' THEN excluded.remote_target ELSE mcptt_calls.remote_target END,
route_set=CASE WHEN excluded.route_set != '' THEN excluded.route_set ELSE mcptt_calls.route_set END,
local_tag=CASE WHEN excluded.local_tag != '' THEN excluded.local_tag ELSE mcptt_calls.local_tag END,
remote_tag=CASE WHEN excluded.remote_tag != '' THEN excluded.remote_tag ELSE mcptt_calls.remote_tag END,
transport=CASE WHEN excluded.transport != '' THEN excluded.transport ELSE mcptt_calls.transport END,
source_addr=CASE WHEN excluded.source_addr != '' THEN excluded.source_addr ELSE mcptt_calls.source_addr END,
audio_ip=CASE WHEN excluded.audio_ip != '' THEN excluded.audio_ip ELSE mcptt_calls.audio_ip END,
audio_port=CASE WHEN excluded.audio_port != 0 THEN excluded.audio_port ELSE mcptt_calls.audio_port END,
audio_proto=CASE WHEN excluded.audio_proto != '' THEN excluded.audio_proto ELSE mcptt_calls.audio_proto END,
audio_payloads=CASE WHEN excluded.audio_payloads != '[]' THEN excluded.audio_payloads ELSE mcptt_calls.audio_payloads END,
floor_control_ip=CASE WHEN excluded.floor_control_ip != '' THEN excluded.floor_control_ip ELSE mcptt_calls.floor_control_ip END,
floor_control_port=CASE WHEN excluded.floor_control_port != 0 THEN excluded.floor_control_port ELSE mcptt_calls.floor_control_port END,
floor_control_proto=CASE WHEN excluded.floor_control_proto != '' THEN excluded.floor_control_proto ELSE mcptt_calls.floor_control_proto END,
floor_control_payloads=CASE WHEN excluded.floor_control_payloads != '[]' THEN excluded.floor_control_payloads ELSE mcptt_calls.floor_control_payloads END,
media_attributes=CASE WHEN excluded.media_attributes != '[]' THEN excluded.media_attributes ELSE mcptt_calls.media_attributes END,
floor_control_attrs=CASE WHEN excluded.floor_control_attrs != '[]' THEN excluded.floor_control_attrs ELSE mcptt_calls.floor_control_attrs END,
local_audio_port=CASE WHEN excluded.local_audio_port != 0 THEN excluded.local_audio_port ELSE mcptt_calls.local_audio_port END,
local_rtcp_port=CASE WHEN excluded.local_rtcp_port != 0 THEN excluded.local_rtcp_port ELSE mcptt_calls.local_rtcp_port END,
local_floor_port=CASE WHEN excluded.local_floor_port != 0 THEN excluded.local_floor_port ELSE mcptt_calls.local_floor_port END,
sdp_offer=CASE WHEN excluded.sdp_offer != '' THEN excluded.sdp_offer ELSE mcptt_calls.sdp_offer END,
sdp_answer=CASE WHEN excluded.sdp_answer != '' THEN excluded.sdp_answer ELSE mcptt_calls.sdp_answer END,
updated_at=excluded.updated_at,
answered_at=CASE WHEN excluded.answered_at != '' THEN excluded.answered_at ELSE mcptt_calls.answered_at END,
established_at=CASE WHEN excluded.established_at != '' THEN excluded.established_at ELSE mcptt_calls.established_at END,
terminated_at=CASE WHEN excluded.terminated_at != '' THEN excluded.terminated_at ELSE mcptt_calls.terminated_at END`),
		v.ID, v.CallID, v.State, v.InitiatorURI, v.TargetURI, v.GroupURI, v.MCPTTID, v.RemoteTarget, v.RouteSet,
		v.LocalTag, v.RemoteTag, v.Transport, v.SourceAddr, v.AudioIP, v.AudioPort, v.AudioProto, marshalStrings(v.AudioPayloads),
		v.FloorControlIP, v.FloorControlPort, v.FloorControlProto, marshalStrings(v.FloorControlPayloads),
		marshalStrings(v.MediaAttributes), marshalStrings(v.FloorControlAttrs), v.LocalAudioPort, v.LocalRTCPPort, v.LocalFloorPort,
		v.RTPPackets, v.RTPBytes, v.RTPRejectedPackets, v.RTPRejectedBytes, v.RTPPayloadType, v.RTPSSRC, v.RTPFirstSequence, v.RTPLastSequence, v.RTPLastTimestamp,
		v.RTPSequenceCycles, v.RTPExpectedPackets, v.RTPLostPackets, v.RTPJitter, v.RTCPPackets, v.RTCPBytes, v.FloorPackets, v.FloorBytes,
		formatTime(v.LastRTPAt), formatTime(v.LastRTCPAt), formatTime(v.LastFloorAt), v.SDPOffer, v.SDPAnswer,
		formatTime(v.CreatedAt), formatTime(v.UpdatedAt), formatTime(v.AnsweredAt), formatTime(v.EstablishedAt),
		formatTime(v.TerminatedAt))
	return v, err
}

func (s *Store) ListCalls(ctx context.Context) ([]store.MCPTTCall, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, call_id, state, initiator_uri, target_uri, group_uri, mcptt_id,
remote_target, route_set, local_tag, remote_tag, transport, source_addr, audio_ip, audio_port, audio_proto,
audio_payloads, floor_control_ip, floor_control_port, floor_control_proto, floor_control_payloads,
media_attributes, floor_control_attrs, local_audio_port, local_rtcp_port, local_floor_port, rtp_packets, rtp_bytes,
rtp_rejected_packets, rtp_rejected_bytes, rtp_payload_type, rtp_ssrc, rtp_first_sequence, rtp_last_sequence, rtp_last_timestamp, rtp_sequence_cycles,
rtp_expected_packets, rtp_lost_packets, rtp_jitter, rtcp_packets, rtcp_bytes, floor_packets, floor_bytes,
floor_state, floor_last_event, floor_last_subtype, floor_ssrc, floor_holder, floor_granted_at, floor_released_at, floor_updated_at,
last_rtp_at, last_rtcp_at, last_floor_at, sdp_offer, sdp_answer, created_at, updated_at, answered_at,
established_at, terminated_at, session_expires_at
FROM mcptt_calls ORDER BY updated_at DESC, call_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.MCPTTCall
	for rows.Next() {
		v, err := scanCall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) ListCallsByGroup(ctx context.Context, groupURI string) ([]store.MCPTTCall, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, call_id, state, initiator_uri, target_uri, group_uri, mcptt_id,
remote_target, route_set, local_tag, remote_tag, transport, source_addr, audio_ip, audio_port, audio_proto,
audio_payloads, floor_control_ip, floor_control_port, floor_control_proto, floor_control_payloads,
media_attributes, floor_control_attrs, local_audio_port, local_rtcp_port, local_floor_port, rtp_packets, rtp_bytes,
rtp_rejected_packets, rtp_rejected_bytes, rtp_payload_type, rtp_ssrc, rtp_first_sequence, rtp_last_sequence, rtp_last_timestamp, rtp_sequence_cycles,
rtp_expected_packets, rtp_lost_packets, rtp_jitter, rtcp_packets, rtcp_bytes, floor_packets, floor_bytes,
floor_state, floor_last_event, floor_last_subtype, floor_ssrc, floor_holder, floor_granted_at, floor_released_at, floor_updated_at,
last_rtp_at, last_rtcp_at, last_floor_at, sdp_offer, sdp_answer, created_at, updated_at, answered_at,
established_at, terminated_at, session_expires_at
FROM mcptt_calls WHERE group_uri = ? AND state NOT IN ('terminated', 'cancelled') ORDER BY updated_at DESC`), groupURI)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.MCPTTCall
	for rows.Next() {
		v, err := scanCall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) SetUEContactIP(ctx context.Context, ueIP, mcpttID string) error {
	now := formatTime(time.Now().UTC())
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO ue_contacts (ue_ip, mcptt_id, updated_at) VALUES (?, ?, ?)
ON CONFLICT(ue_ip) DO UPDATE SET mcptt_id = excluded.mcptt_id, updated_at = excluded.updated_at`),
		ueIP, mcpttID, now)
	return err
}

func (s *Store) GetMCPTTIDByUEIP(ctx context.Context, ueIP string) (string, error) {
	var mcpttID string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT mcptt_id FROM ue_contacts WHERE ue_ip = ?`), ueIP).Scan(&mcpttID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return mcpttID, err
}

func (s *Store) GetCall(ctx context.Context, callID string) (*store.MCPTTCall, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT id, call_id, state, initiator_uri, target_uri, group_uri, mcptt_id,
remote_target, route_set, local_tag, remote_tag, transport, source_addr, audio_ip, audio_port, audio_proto,
audio_payloads, floor_control_ip, floor_control_port, floor_control_proto, floor_control_payloads,
media_attributes, floor_control_attrs, local_audio_port, local_rtcp_port, local_floor_port, rtp_packets, rtp_bytes,
rtp_rejected_packets, rtp_rejected_bytes, rtp_payload_type, rtp_ssrc, rtp_first_sequence, rtp_last_sequence, rtp_last_timestamp, rtp_sequence_cycles,
rtp_expected_packets, rtp_lost_packets, rtp_jitter, rtcp_packets, rtcp_bytes, floor_packets, floor_bytes,
floor_state, floor_last_event, floor_last_subtype, floor_ssrc, floor_holder, floor_granted_at, floor_released_at, floor_updated_at,
last_rtp_at, last_rtcp_at, last_floor_at, sdp_offer, sdp_answer, created_at, updated_at, answered_at,
established_at, terminated_at, session_expires_at
FROM mcptt_calls WHERE call_id = ?`), callID)
	v, err := scanCall(row)
	if ok, err := notFound(err); ok || err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Store) UpdateCallState(ctx context.Context, callID, state string) error {
	now := time.Now().UTC()
	assignments := `state = ?, updated_at = ?`
	args := []any{state, formatTime(now)}
	switch state {
	case "answered":
		assignments += `, answered_at = CASE WHEN answered_at = '' THEN ? ELSE answered_at END`
		args = append(args, formatTime(now))
	case "established":
		assignments += `, established_at = CASE WHEN established_at = '' THEN ? ELSE established_at END`
		args = append(args, formatTime(now))
	case "terminated", "cancelled":
		assignments += `, terminated_at = CASE WHEN terminated_at = '' THEN ? ELSE terminated_at END`
		args = append(args, formatTime(now))
	}
	args = append(args, callID)
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE mcptt_calls SET `+assignments+` WHERE call_id = ?`), args...)
	return err
}

// RefreshCallSession records the RFC 4028 session expiration set at answer
// time or extended by a session refresh request.
func (s *Store) RefreshCallSession(ctx context.Context, callID string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE mcptt_calls SET session_expires_at = ?, updated_at = ? WHERE call_id = ?`),
		formatTime(expiresAt), formatTime(time.Now().UTC()), callID)
	return err
}

func (s *Store) IncrementCallMedia(ctx context.Context, callID, kind string, bytes int) error {
	now := formatTime(time.Now().UTC())
	switch kind {
	case "rtp":
		_, err := s.db.ExecContext(ctx, s.q(`UPDATE mcptt_calls SET rtp_packets = rtp_packets + 1, rtp_bytes = rtp_bytes + ?, last_rtp_at = ?, updated_at = ? WHERE call_id = ?`),
			bytes, now, now, callID)
		return err
	case "rtp_rejected":
		_, err := s.db.ExecContext(ctx, s.q(`UPDATE mcptt_calls SET rtp_rejected_packets = rtp_rejected_packets + 1, rtp_rejected_bytes = rtp_rejected_bytes + ?, last_rtp_at = ?, updated_at = ? WHERE call_id = ?`),
			bytes, now, now, callID)
		return err
	case "rtcp":
		_, err := s.db.ExecContext(ctx, s.q(`UPDATE mcptt_calls SET rtcp_packets = rtcp_packets + 1, rtcp_bytes = rtcp_bytes + ?, last_rtcp_at = ?, updated_at = ? WHERE call_id = ?`),
			bytes, now, now, callID)
		return err
	case "floor":
		_, err := s.db.ExecContext(ctx, s.q(`UPDATE mcptt_calls SET floor_packets = floor_packets + 1, floor_bytes = floor_bytes + ?, last_floor_at = ?, updated_at = ? WHERE call_id = ?`),
			bytes, now, now, callID)
		return err
	default:
		return fmt.Errorf("unknown media kind %q", kind)
	}
}

func (s *Store) UpdateCallRTPStats(ctx context.Context, callID string, stats store.RTPStatsUpdate) error {
	now := formatTime(time.Now().UTC())
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE mcptt_calls SET
rtp_payload_type = ?,
rtp_ssrc = ?,
rtp_first_sequence = ?,
rtp_last_sequence = ?,
rtp_last_timestamp = ?,
rtp_sequence_cycles = ?,
rtp_expected_packets = ?,
rtp_lost_packets = ?,
rtp_jitter = ?,
updated_at = ?
WHERE call_id = ?`),
		stats.PayloadType, stats.SSRC, stats.FirstSequence, stats.LastSequence, stats.LastTimestamp,
		stats.SequenceCycles, stats.ExpectedPackets, stats.LostPackets, stats.Jitter, now, callID)
	return err
}

func (s *Store) UpdateCallFloorState(ctx context.Context, callID string, update store.FloorStateUpdate) (bool, error) {
	if update.State == "" {
		update.State = "unknown"
	}
	if update.Event == "" {
		update.Event = update.State
	}
	now := time.Now().UTC()
	at := update.At
	if at.IsZero() {
		at = now
	}
	assignments := `floor_state = ?, floor_last_event = ?, floor_last_subtype = ?, floor_ssrc = ?, floor_updated_at = ?, updated_at = ?`
	args := []any{update.State, update.Event, update.Subtype, update.SSRC, formatTime(at), formatTime(now)}
	if update.Holder != "" {
		assignments += `, floor_holder = ?`
		args = append(args, update.Holder)
	} else if update.ClearHolder {
		assignments += `, floor_holder = ''`
	}
	switch update.State {
	case "granted", "taken":
		assignments += `, floor_granted_at = CASE WHEN floor_granted_at = '' THEN ? ELSE floor_granted_at END`
		args = append(args, formatTime(at))
	case "released", "idle", "revoked":
		assignments += `, floor_released_at = ?`
		args = append(args, formatTime(at))
	}
	args = append(args, callID)
	query := `UPDATE mcptt_calls SET ` + assignments + ` WHERE call_id = ?`
	if update.ExpectHolder != nil {
		// Compare-and-swap: apply only if the holder is still what the caller
		// based its decision on.
		query += ` AND floor_holder = ?`
		args = append(args, *update.ExpectHolder)
	}

	res, err := s.db.ExecContext(ctx, s.q(query), args...)
	if err != nil {
		return false, err
	}
	if update.ExpectHolder == nil {
		return true, nil
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func (s *Store) CallSummary(ctx context.Context) (store.CallSummary, error) {
	calls, err := s.ListCalls(ctx)
	if err != nil {
		return store.CallSummary{}, err
	}
	dialogs, err := s.ListDialogs(ctx)
	if err != nil {
		return store.CallSummary{}, err
	}
	var out store.CallSummary
	out.SIPDialogs = len(dialogs)
	cutoff := time.Now().UTC().Add(-15 * time.Minute)
	for _, c := range calls {
		if !c.UpdatedAt.IsZero() && (out.LastEventAt == nil || c.UpdatedAt.After(*out.LastEventAt)) {
			t := c.UpdatedAt
			out.LastEventAt = &t
		}
		out.TotalRTPPackets += c.RTPPackets
		out.TotalRTPBytes += c.RTPBytes
		out.TotalRTPLostPackets += c.RTPLostPackets
		if c.RTPJitter > out.MaxRTPJitter {
			out.MaxRTPJitter = c.RTPJitter
		}
		for _, t := range []time.Time{c.LastRTPAt, c.LastRTCPAt, c.LastFloorAt} {
			if !t.IsZero() && (out.LastMediaAt == nil || t.After(*out.LastMediaAt)) {
				tt := t
				out.LastMediaAt = &tt
			}
		}
		active := false
		switch c.State {
		case "invited", "ringing", "answered":
			out.ActiveCalls++
			out.EarlyCalls++
			active = true
		case "established":
			out.ActiveCalls++
			out.EstablishedCalls++
			active = true
		case "terminating":
			out.ActiveCalls++
			out.TerminatingCalls++
			active = true
		case "terminated", "cancelled":
			out.TerminatedCallsTotal++
		}
		if active && c.RTPPackets > 0 {
			out.ActiveRTPCalls++
		}
		if active && (c.FloorState == "granted" || c.FloorState == "taken") {
			out.FloorGrantedCalls++
		}
		if (c.State == "terminated" || c.State == "cancelled") && c.TerminatedAt.After(cutoff) {
			out.RecentlyEnded++
		}
		if c.State == "terminated" && !c.TerminatedAt.IsZero() && (out.LastBYEAt == nil || c.TerminatedAt.After(*out.LastBYEAt)) {
			t := c.TerminatedAt
			out.LastBYEAt = &t
		}
	}
	return out, nil
}

func (s *Store) UpsertRegistration(ctx context.Context, v store.Registration) (store.Registration, error) {
	now := time.Now().UTC()
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	if v.LastSeenAt.IsZero() {
		v.LastSeenAt = now
	}
	if v.RegistrationSource == "" {
		v.RegistrationSource = "third_party_register"
	}
	if v.State == "" {
		if v.Registered {
			v.State = "registered"
		} else {
			v.State = "unregistered"
		}
	}
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO mcptt_registrations (
id, public_identity, imsi, msisdn, mcptt_id, contact_uri, contact_raw, source_ip, source_port,
transport, call_id, cseq, registered, state, expires_at, expires_seconds, last_registered_at,
last_unregistered_at, last_seen_at, user_agent, feature_tags, icsi_refs, scscf_identity, registration_source)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(public_identity) DO UPDATE SET
imsi=excluded.imsi,
msisdn=excluded.msisdn,
mcptt_id=excluded.mcptt_id,
contact_uri=excluded.contact_uri,
contact_raw=excluded.contact_raw,
source_ip=excluded.source_ip,
source_port=excluded.source_port,
transport=excluded.transport,
call_id=excluded.call_id,
cseq=excluded.cseq,
registered=excluded.registered,
state=excluded.state,
expires_at=excluded.expires_at,
expires_seconds=excluded.expires_seconds,
last_registered_at=CASE WHEN excluded.last_registered_at != '' THEN excluded.last_registered_at ELSE mcptt_registrations.last_registered_at END,
last_unregistered_at=CASE WHEN excluded.last_unregistered_at != '' THEN excluded.last_unregistered_at ELSE mcptt_registrations.last_unregistered_at END,
last_seen_at=excluded.last_seen_at,
user_agent=excluded.user_agent,
feature_tags=excluded.feature_tags,
icsi_refs=excluded.icsi_refs,
scscf_identity=excluded.scscf_identity,
registration_source=excluded.registration_source`),
		v.ID, v.PublicIdentity, v.IMSI, v.MSISDN, v.MCPTTID, v.ContactURI, v.ContactRaw, v.SourceIP, v.SourcePort,
		v.Transport, v.CallID, v.CSeq, boolInt(v.Registered), v.State, formatTime(v.ExpiresAt), v.ExpiresSeconds,
		formatTime(v.LastRegisteredAt), formatTime(v.LastUnregisteredAt), formatTime(v.LastSeenAt), v.UserAgent,
		marshalStrings(v.FeatureTags), marshalStrings(v.ICSIRefs), v.SCSCFIdentity, v.RegistrationSource)
	return v, err
}

func (s *Store) ListRegistrations(ctx context.Context) ([]store.Registration, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, public_identity, imsi, msisdn, mcptt_id, contact_uri, contact_raw,
source_ip, source_port, transport, call_id, cseq, registered, state, expires_at, expires_seconds,
last_registered_at, last_unregistered_at, last_seen_at, user_agent, feature_tags, icsi_refs, scscf_identity,
registration_source FROM mcptt_registrations ORDER BY last_seen_at DESC, public_identity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Registration
	for rows.Next() {
		v, err := scanRegistration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetRegistration(ctx context.Context, publicIdentity string) (*store.Registration, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT id, public_identity, imsi, msisdn, mcptt_id, contact_uri, contact_raw,
source_ip, source_port, transport, call_id, cseq, registered, state, expires_at, expires_seconds,
last_registered_at, last_unregistered_at, last_seen_at, user_agent, feature_tags, icsi_refs, scscf_identity,
registration_source FROM mcptt_registrations WHERE public_identity = ?`), publicIdentity)
	v, err := scanRegistration(row)
	if ok, err := notFound(err); ok || err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Store) RegistrationSummary(ctx context.Context) (store.RegistrationSummary, error) {
	regs, err := s.ListRegistrations(ctx)
	if err != nil {
		return store.RegistrationSummary{}, err
	}
	seenUsers := map[string]struct{}{}
	var out store.RegistrationSummary
	cutoff := time.Now().UTC().Add(-15 * time.Minute)
	for _, r := range regs {
		if !r.LastSeenAt.IsZero() && (out.LastEventAt == nil || r.LastSeenAt.After(*out.LastEventAt)) {
			t := r.LastSeenAt
			out.LastEventAt = &t
		}
		if r.Registered && r.State == "registered" {
			out.RegisteredClients++
			seenUsers[r.PublicIdentity] = struct{}{}
		}
		if r.State == "expired" {
			out.ExpiredRegistrations++
		}
		if r.State == "unregistered" && r.LastUnregisteredAt.After(cutoff) {
			out.UnregisteredRecent++
		}
	}
	out.RegisteredUsers = len(seenUsers)
	return out, nil
}

func (s *Store) ExpireRegistrations(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE mcptt_registrations
SET registered = 0, state = 'expired', last_seen_at = ?
WHERE registered != 0 AND expires_at != '' AND expires_at <= ?`), formatTime(now), formatTime(now))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

type registrationScanner interface {
	Scan(dest ...any) error
}

type callScanner interface {
	Scan(dest ...any) error
}

type dialogScanner interface {
	Scan(dest ...any) error
}

func scanDialog(row dialogScanner) (store.Dialog, error) {
	var v store.Dialog
	var recordRouteUsed int
	var created, updated string
	err := row.Scan(&v.ID, &v.CallID, &v.LocalTag, &v.RemoteTag, &v.FromURI, &v.ToURI, &v.RequestURI,
		&v.IMPU, &v.MCPTTID, &v.Method, &v.State, &v.RouteSet, &v.RemoteTarget, &recordRouteUsed,
		&v.LocalCSeq, &v.RemoteCSeq, &v.LastMethod, &v.LastStatus, &v.Transport, &v.SourceAddr,
		&v.TopVia, &created, &updated)
	if err != nil {
		return v, err
	}
	v.RecordRouteUsed = scanBool(recordRouteUsed)
	v.CreatedAt = parseTime(created)
	v.UpdatedAt = parseTime(updated)
	return v, nil
}

func scanCall(row callScanner) (store.MCPTTCall, error) {
	var v store.MCPTTCall
	var created, updated, answered, established, terminated, sessionExpires, lastRTP, lastRTCP, lastFloor string
	var floorGranted, floorReleased, floorUpdated string
	var audioPayloads, floorPayloads, mediaAttrs, floorAttrs string
	err := row.Scan(&v.ID, &v.CallID, &v.State, &v.InitiatorURI, &v.TargetURI, &v.GroupURI, &v.MCPTTID,
		&v.RemoteTarget, &v.RouteSet, &v.LocalTag, &v.RemoteTag, &v.Transport, &v.SourceAddr,
		&v.AudioIP, &v.AudioPort, &v.AudioProto, &audioPayloads,
		&v.FloorControlIP, &v.FloorControlPort, &v.FloorControlProto, &floorPayloads,
		&mediaAttrs, &floorAttrs, &v.LocalAudioPort, &v.LocalRTCPPort, &v.LocalFloorPort, &v.RTPPackets, &v.RTPBytes,
		&v.RTPRejectedPackets, &v.RTPRejectedBytes, &v.RTPPayloadType, &v.RTPSSRC, &v.RTPFirstSequence, &v.RTPLastSequence, &v.RTPLastTimestamp,
		&v.RTPSequenceCycles, &v.RTPExpectedPackets, &v.RTPLostPackets, &v.RTPJitter,
		&v.RTCPPackets, &v.RTCPBytes, &v.FloorPackets, &v.FloorBytes,
		&v.FloorState, &v.FloorLastEvent, &v.FloorLastSubtype, &v.FloorSSRC, &v.FloorHolder, &floorGranted, &floorReleased, &floorUpdated,
		&lastRTP, &lastRTCP, &lastFloor, &v.SDPOffer, &v.SDPAnswer,
		&created, &updated, &answered, &established, &terminated, &sessionExpires)
	if err != nil {
		return v, err
	}
	v.AudioPayloads = unmarshalStrings(audioPayloads)
	v.FloorControlPayloads = unmarshalStrings(floorPayloads)
	v.MediaAttributes = unmarshalStrings(mediaAttrs)
	v.FloorControlAttrs = unmarshalStrings(floorAttrs)
	v.LastRTPAt = parseTime(lastRTP)
	v.LastRTCPAt = parseTime(lastRTCP)
	v.LastFloorAt = parseTime(lastFloor)
	v.FloorGrantedAt = parseTime(floorGranted)
	v.FloorReleasedAt = parseTime(floorReleased)
	v.FloorUpdatedAt = parseTime(floorUpdated)
	v.CreatedAt = parseTime(created)
	v.UpdatedAt = parseTime(updated)
	v.AnsweredAt = parseTime(answered)
	v.EstablishedAt = parseTime(established)
	v.TerminatedAt = parseTime(terminated)
	v.SessionExpiresAt = parseTime(sessionExpires)
	return v, nil
}

func scanRegistration(row registrationScanner) (store.Registration, error) {
	var v store.Registration
	var registered int
	var expiresAt, lastRegistered, lastUnregistered, lastSeen, features, icsi string
	err := row.Scan(&v.ID, &v.PublicIdentity, &v.IMSI, &v.MSISDN, &v.MCPTTID, &v.ContactURI, &v.ContactRaw,
		&v.SourceIP, &v.SourcePort, &v.Transport, &v.CallID, &v.CSeq, &registered, &v.State, &expiresAt,
		&v.ExpiresSeconds, &lastRegistered, &lastUnregistered, &lastSeen, &v.UserAgent, &features, &icsi,
		&v.SCSCFIdentity, &v.RegistrationSource)
	if err != nil {
		return v, err
	}
	v.Registered = scanBool(registered)
	v.ExpiresAt = parseTime(expiresAt)
	v.LastRegisteredAt = parseTime(lastRegistered)
	v.LastUnregisteredAt = parseTime(lastUnregistered)
	v.LastSeenAt = parseTime(lastSeen)
	v.FeatureTags = unmarshalStrings(features)
	v.ICSIRefs = unmarshalStrings(icsi)
	return v, nil
}
