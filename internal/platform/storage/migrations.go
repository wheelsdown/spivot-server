package storage

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const migrationsDir = "migrations"

var migrationFilePattern = regexp.MustCompile(`^([0-9]{6})_([a-z0-9_]+)\.sql$`)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migration describes one ordered database schema migration.
type Migration struct {
	// Version is the monotonically increasing migration version.
	Version int
	// Name is the descriptive migration name from the filename.
	Name string
	// Path is the embedded filesystem path for the migration.
	Path string
	// SQL is the migration body.
	SQL string
}

// Migrations returns the embedded database schema migrations in version order.
func Migrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFiles, migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	migrations := make([]Migration, 0, len(entries))
	seen := make(map[int]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		matches := migrationFilePattern.FindStringSubmatch(name)
		if matches == nil {
			return nil, fmt.Errorf("invalid migration filename %q", name)
		}

		version, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("parse migration version %q: %w", name, err)
		}
		if previous, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate migration version %d in %q and %q", version, previous, name)
		}
		seen[version] = name

		path := migrationsDir + "/" + name
		body, err := migrationFiles.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", name, err)
		}
		sql := strings.TrimSpace(string(body))
		if sql == "" {
			return nil, fmt.Errorf("migration %q is empty", name)
		}

		migrations = append(migrations, Migration{
			Version: version,
			Name:    matches[2],
			Path:    path,
			SQL:     sql,
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	for i, migration := range migrations {
		expected := i + 1
		if migration.Version != expected {
			return nil, fmt.Errorf("migration versions must be contiguous: got %d, expected %d", migration.Version, expected)
		}
	}

	return migrations, nil
}
