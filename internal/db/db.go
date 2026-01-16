package db

import (
	"context"
	"embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5"
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

	// Read migration file
	content, err := migrationsFS.ReadFile("migrations/001_initial_schema.sql")
	if err != nil {
		return fmt.Errorf("read migration file: %w", err)
	}

	// Execute migration
	_, err = db.pool.Exec(ctx, string(content))
	if err != nil {
		return fmt.Errorf("execute migration: %w", err)
	}

	log.Info("database migrations completed")
	return nil
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
