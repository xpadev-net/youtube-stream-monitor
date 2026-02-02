package db

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xpadev-net/youtube-stream-tracker/internal/log"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps the database connection pool.
type DB struct {
	pool *pgxpool.Pool
}

// New creates a new database connection.
func New(ctx context.Context, databaseURL string) (*DB, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}

	config.MaxConns = 25
	config.MinConns = 5
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	log.Info("database connection established")

	return &DB{pool: pool}, nil
}

// Close closes the database connection pool.
func (db *DB) Close() {
	db.pool.Close()
	log.Info("database connection closed")
}

// Pool returns the underlying connection pool.
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}

// Migrate runs all database migrations.
func (db *DB) Migrate(ctx context.Context) error {
	log.Info("running database migrations")

	if err := db.ensureSchemaMigrations(ctx); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	files, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	var migrationFiles []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		migrationFiles = append(migrationFiles, name)
	}
	if len(migrationFiles) == 0 {
		log.Info("no migrations found")
		return nil
	}
	sort.Strings(migrationFiles)

	applied, err := db.getAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}

	for _, name := range migrationFiles {
		if applied[name] {
			continue
		}
		if name == "001_initial_schema.sql" {
			already, err := db.hasCoreSchema(ctx)
			if err != nil {
				return fmt.Errorf("check core schema: %w", err)
			}
			if already {
				if err := db.recordMigration(ctx, name); err != nil {
					return fmt.Errorf("record baseline migration: %w", err)
				}
				applied[name] = true
				log.Info("baseline migration already applied", zap.String("version", name))
				continue
			}
		}

		content, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration file %s: %w", name, err)
		}
		if err := db.applyMigration(ctx, name, string(content)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		applied[name] = true
		log.Info("applied migration", zap.String("version", name))
	}

	log.Info("database migrations completed")
	return nil
}

func (db *DB) ensureSchemaMigrations(ctx context.Context) error {
	_, err := db.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL
		)
	`)
	return err
}

func (db *DB) getAppliedMigrations(ctx context.Context) (map[string]bool, error) {
	applied := make(map[string]bool)
	rows, err := db.pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

func (db *DB) recordMigration(ctx context.Context, version string) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO schema_migrations (version, applied_at)
		VALUES ($1, NOW())
		ON CONFLICT (version) DO NOTHING
	`, version)
	return err
}

func (db *DB) applyMigration(ctx context.Context, version, sql string) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, sql); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO schema_migrations (version, applied_at)
		VALUES ($1, NOW())
		ON CONFLICT (version) DO NOTHING
	`, version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (db *DB) hasCoreSchema(ctx context.Context) (bool, error) {
	var exists bool
	err := db.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'monitors'
		)
	`).Scan(&exists)
	return exists, err
}

// Health checks database connectivity.
func (db *DB) Health(ctx context.Context) error {
	return db.pool.Ping(ctx)
}

// BeginTx starts a new transaction.
func (db *DB) BeginTx(ctx context.Context) (*Tx, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	return &Tx{tx: tx}, nil
}

// Tx wraps a database transaction.
type Tx struct {
	tx pgx.Tx
}

// Exec executes a query without returning rows.
func (t *Tx) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return t.tx.Exec(ctx, sql, args...)
}

// QueryRow executes a query expected to return at most one row.
func (t *Tx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return t.tx.QueryRow(ctx, sql, args...)
}

// Query executes a query that returns rows.
func (t *Tx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return t.tx.Query(ctx, sql, args...)
}

// Commit commits the transaction.
func (t *Tx) Commit(ctx context.Context) error {
	return t.tx.Commit(ctx)
}

// Rollback rolls back the transaction.
func (t *Tx) Rollback(ctx context.Context) error {
	return t.tx.Rollback(ctx)
}

// LogQueryError logs a query error with context.
func LogQueryError(operation string, err error) {
	log.Error("database query error",
		zap.String("operation", operation),
		zap.Error(err),
	)
}
