package sqlite

import (
	"context"
	"testing"
)

func TestMigrationCreatesHotPathIndexes(t *testing.T) {
	st, err := Open(t.TempDir() + "/mcxas.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	rows, err := st.db.QueryContext(context.Background(),
		`SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	found := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		found[n] = true
	}

	for _, want := range []string{
		"idx_mcptt_calls_group_uri",
		"idx_mcptt_calls_audio_ip",
		"idx_mcptt_calls_updated_at",
		"idx_dialogs_call_id",
		"idx_subscriptions_call_id",
		"idx_group_memberships_group_id",
		"idx_group_affiliations_group_id",
		"idx_group_affiliations_expires_at",
		"idx_mcptt_registrations_expires_at",
		"idx_cms_documents_path",
	} {
		if !found[want] {
			t.Errorf("index %s was not created", want)
		}
	}
}
