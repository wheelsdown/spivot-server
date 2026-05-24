package storage

import (
	"strings"
	"testing"
)

func TestMigrationsAreContiguous(t *testing.T) {
	migrations, err := Migrations()
	if err != nil {
		t.Fatalf("Migrations() error = %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("Migrations() returned no migrations")
	}

	for i, migration := range migrations {
		expected := i + 1
		if migration.Version != expected {
			t.Fatalf("migration %q version = %d, expected %d", migration.Path, migration.Version, expected)
		}
		if migration.Name == "" {
			t.Fatalf("migration %q has empty name", migration.Path)
		}
		if strings.TrimSpace(migration.SQL) == "" {
			t.Fatalf("migration %q has empty SQL", migration.Path)
		}
	}
}

func TestOpenCaravanFoundationTables(t *testing.T) {
	migrations, err := Migrations()
	if err != nil {
		t.Fatalf("Migrations() error = %v", err)
	}

	var foundation Migration
	for _, migration := range migrations {
		if migration.Version == 1 {
			foundation = migration
			break
		}
	}
	if foundation.Version == 0 {
		t.Fatal("foundation migration not found")
	}

	requiredTables := []string{
		"schema_migrations",
		"server_policy_snapshots",
		"federated_servers",
		"accounts",
		"account_devices",
		"vehicles",
		"journeys",
		"journey_invites",
		"journey_participants",
		"journey_policy_acceptances",
		"participant_sessions",
		"journey_segments",
		"telemetry_batches",
		"position_samples",
	}

	for _, table := range requiredTables {
		want := "CREATE TABLE " + table
		if !strings.Contains(foundation.SQL, want) {
			t.Errorf("foundation SQL missing %q", want)
		}
	}
}

func TestOpenCaravanFoundationCapturesSchemaDecisions(t *testing.T) {
	migrations, err := Migrations()
	if err != nil {
		t.Fatalf("Migrations() error = %v", err)
	}
	foundation := migrations[0].SQL

	tests := []struct {
		name string
		want string
	}{
		{
			name: "journeys snapshot policy hash",
			want: "policy_hash TEXT NOT NULL",
		},
		{
			name: "invites store token hash",
			want: "token_hash TEXT NOT NULL UNIQUE",
		},
		{
			name: "position coordinates use e7 integer degrees",
			want: "latitude_e7 INTEGER NOT NULL",
		},
		{
			name: "telemetry batches dedupe client uploads",
			want: "UNIQUE (device_id, client_batch_id)",
		},
		{
			name: "samples dedupe participant sequence numbers",
			want: "UNIQUE (journey_id, participant_id, client_sequence)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(foundation, tt.want) {
				t.Fatalf("foundation SQL missing %q", tt.want)
			}
		})
	}
}
