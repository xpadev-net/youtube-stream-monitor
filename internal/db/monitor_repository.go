package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrMonitorNotFound  = errors.New("monitor not found")
	ErrDuplicateMonitor = errors.New("duplicate monitor for stream URL")
)

// MonitorRepository handles monitor database operations.
type MonitorRepository struct {
	db *DB
}

// NewMonitorRepository creates a new monitor repository.
func NewMonitorRepository(db *DB) *MonitorRepository {
	return &MonitorRepository{db: db}
}

// CreateMonitorParams contains parameters for creating a monitor.
type CreateMonitorParams struct {
	ID          string
	StreamURL   string
	CallbackURL string
	Config      MonitorConfig
	Metadata    json.RawMessage
}

// Create creates a new monitor and its associated stats record.
func (r *MonitorRepository) Create(ctx context.Context, params CreateMonitorParams) (*Monitor, error) {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	configJSON, err := json.Marshal(params.Config)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	metadata := params.Metadata
	if metadata == nil {
		metadata = json.RawMessage("{}")
	}

	var monitor Monitor
	err = tx.QueryRow(ctx, `
		INSERT INTO monitors (id, stream_url, callback_url, config, metadata, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, stream_url, callback_url, config, metadata, status, pod_name, created_at, updated_at
	`, params.ID, params.StreamURL, params.CallbackURL, configJSON, metadata, StatusInitializing).Scan(
		&monitor.ID,
		&monitor.StreamURL,
		&monitor.CallbackURL,
		&configJSON,
		&monitor.Metadata,
		&monitor.Status,
		&monitor.PodName,
		&monitor.CreatedAt,
		&monitor.UpdatedAt,
	)
	if err != nil {
		// Check for unique constraint violation
		if isDuplicateKeyError(err) {
			return nil, ErrDuplicateMonitor
		}
		return nil, fmt.Errorf("insert monitor: %w", err)
	}

	if err := json.Unmarshal(configJSON, &monitor.Config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	// Create associated stats record
	_, err = tx.Exec(ctx, `
		INSERT INTO monitor_stats (monitor_id, video_health, audio_health, stream_status)
		VALUES ($1, $2, $3, $4)
	`, params.ID, HealthUnknown, HealthUnknown, StreamStatusUnknown)
	if err != nil {
		return nil, fmt.Errorf("insert monitor_stats: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	return &monitor, nil
}

// GetByID retrieves a monitor by ID.
func (r *MonitorRepository) GetByID(ctx context.Context, id string) (*Monitor, error) {
	var monitor Monitor
	var configJSON []byte

	err := r.db.pool.QueryRow(ctx, `
		SELECT id, stream_url, callback_url, config, metadata, status, pod_name, created_at, updated_at
		FROM monitors
		WHERE id = $1
	`, id).Scan(
		&monitor.ID,
		&monitor.StreamURL,
		&monitor.CallbackURL,
		&configJSON,
		&monitor.Metadata,
		&monitor.Status,
		&monitor.PodName,
		&monitor.CreatedAt,
		&monitor.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrMonitorNotFound
		}
		return nil, fmt.Errorf("query monitor: %w", err)
	}

	if err := json.Unmarshal(configJSON, &monitor.Config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &monitor, nil
}

// GetWithStats retrieves a monitor with its statistics.
func (r *MonitorRepository) GetWithStats(ctx context.Context, id string) (*MonitorWithStats, error) {
	monitor, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	stats, err := r.GetStats(ctx, id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	return &MonitorWithStats{
		Monitor: *monitor,
		Stats:   stats,
	}, nil
}

// GetStats retrieves monitor statistics.
func (r *MonitorRepository) GetStats(ctx context.Context, monitorID string) (*MonitorStats, error) {
	var stats MonitorStats

	err := r.db.pool.QueryRow(ctx, `
		SELECT monitor_id, total_segments, blackout_events, silence_events, last_check_at, video_health, audio_health, stream_status
		FROM monitor_stats
		WHERE monitor_id = $1
	`, monitorID).Scan(
		&stats.MonitorID,
		&stats.TotalSegments,
		&stats.BlackoutEvents,
		&stats.SilenceEvents,
		&stats.LastCheckAt,
		&stats.VideoHealth,
		&stats.AudioHealth,
		&stats.StreamStatus,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("query monitor_stats: %w", err)
	}

	return &stats, nil
}

// ListParams contains parameters for listing monitors.
type ListParams struct {
	Status *MonitorStatus
	Limit  int
	Offset int
}

// List retrieves monitors with optional filtering.
func (r *MonitorRepository) List(ctx context.Context, params ListParams) ([]*Monitor, int, error) {
	// Set defaults
	if params.Limit <= 0 {
		params.Limit = 50
	}
	if params.Limit > 100 {
		params.Limit = 100
	}

	// Build query
	baseQuery := "FROM monitors"
	var args []interface{}
	argIdx := 1

	if params.Status != nil {
		baseQuery += fmt.Sprintf(" WHERE status = $%d", argIdx)
		args = append(args, *params.Status)
		argIdx++
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) " + baseQuery
	if err := r.db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count monitors: %w", err)
	}

	// Fetch monitors
	selectQuery := fmt.Sprintf(`
		SELECT id, stream_url, callback_url, config, metadata, status, pod_name, created_at, updated_at
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, baseQuery, argIdx, argIdx+1)
	args = append(args, params.Limit, params.Offset)

	rows, err := r.db.pool.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query monitors: %w", err)
	}
	defer rows.Close()

	var monitors []*Monitor
	for rows.Next() {
		var monitor Monitor
		var configJSON []byte

		if err := rows.Scan(
			&monitor.ID,
			&monitor.StreamURL,
			&monitor.CallbackURL,
			&configJSON,
			&monitor.Metadata,
			&monitor.Status,
			&monitor.PodName,
			&monitor.CreatedAt,
			&monitor.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan monitor: %w", err)
		}

		if err := json.Unmarshal(configJSON, &monitor.Config); err != nil {
			return nil, 0, fmt.Errorf("unmarshal config: %w", err)
		}

		monitors = append(monitors, &monitor)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate monitors: %w", err)
	}

	return monitors, total, nil
}

// UpdateStatus updates the status of a monitor.
func (r *MonitorRepository) UpdateStatus(ctx context.Context, id string, status MonitorStatus) error {
	result, err := r.db.pool.Exec(ctx, `
		UPDATE monitors SET status = $2, updated_at = NOW() WHERE id = $1
	`, id, status)
	if err != nil {
		return fmt.Errorf("update monitor status: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrMonitorNotFound
	}

	return nil
}

// UpdateStatusWithCondition updates the status only if the current status matches.
func (r *MonitorRepository) UpdateStatusWithCondition(ctx context.Context, id string, currentStatus, newStatus MonitorStatus) (bool, error) {
	result, err := r.db.pool.Exec(ctx, `
		UPDATE monitors SET status = $3, updated_at = NOW() WHERE id = $1 AND status = $2
	`, id, currentStatus, newStatus)
	if err != nil {
		return false, fmt.Errorf("update monitor status: %w", err)
	}

	return result.RowsAffected() > 0, nil
}

// UpdatePodName updates the pod name for a monitor.
func (r *MonitorRepository) UpdatePodName(ctx context.Context, id string, podName string) error {
	result, err := r.db.pool.Exec(ctx, `
		UPDATE monitors SET pod_name = $2, updated_at = NOW() WHERE id = $1
	`, id, podName)
	if err != nil {
		return fmt.Errorf("update pod name: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrMonitorNotFound
	}

	return nil
}

// UpdateStats updates monitor statistics.
func (r *MonitorRepository) UpdateStats(ctx context.Context, stats *MonitorStats) error {
	_, err := r.db.pool.Exec(ctx, `
		UPDATE monitor_stats
		SET total_segments = $2, blackout_events = $3, silence_events = $4,
		    last_check_at = $5, video_health = $6, audio_health = $7, stream_status = $8
		WHERE monitor_id = $1
	`, stats.MonitorID, stats.TotalSegments, stats.BlackoutEvents, stats.SilenceEvents,
		stats.LastCheckAt, stats.VideoHealth, stats.AudioHealth, stats.StreamStatus)
	if err != nil {
		return fmt.Errorf("update monitor_stats: %w", err)
	}

	return nil
}

// Delete removes a monitor and its associated records.
func (r *MonitorRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.pool.Exec(ctx, `DELETE FROM monitors WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete monitor: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrMonitorNotFound
	}

	return nil
}

// GetActiveMonitors returns all monitors with active status.
func (r *MonitorRepository) GetActiveMonitors(ctx context.Context) ([]*Monitor, error) {
	rows, err := r.db.pool.Query(ctx, `
		SELECT id, stream_url, callback_url, config, metadata, status, pod_name, created_at, updated_at
		FROM monitors
		WHERE status IN ($1, $2, $3)
		ORDER BY created_at
	`, StatusInitializing, StatusWaiting, StatusMonitoring)
	if err != nil {
		return nil, fmt.Errorf("query active monitors: %w", err)
	}
	defer rows.Close()

	var monitors []*Monitor
	for rows.Next() {
		var monitor Monitor
		var configJSON []byte

		if err := rows.Scan(
			&monitor.ID,
			&monitor.StreamURL,
			&monitor.CallbackURL,
			&configJSON,
			&monitor.Metadata,
			&monitor.Status,
			&monitor.PodName,
			&monitor.CreatedAt,
			&monitor.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan monitor: %w", err)
		}

		if err := json.Unmarshal(configJSON, &monitor.Config); err != nil {
			return nil, fmt.Errorf("unmarshal config: %w", err)
		}

		monitors = append(monitors, &monitor)
	}

	return monitors, nil
}

// CreateEvent creates a new monitor event.
func (r *MonitorRepository) CreateEvent(ctx context.Context, event *MonitorEvent) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.Must(uuid.NewV7())
	}

	_, err := r.db.pool.Exec(ctx, `
		INSERT INTO monitor_events (id, monitor_id, event_type, payload, webhook_status, webhook_attempts, webhook_last_error, created_at, sent_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, event.ID, event.MonitorID, event.EventType, event.Payload, event.WebhookStatus, event.WebhookAttempts, event.WebhookLastError, time.Now(), event.SentAt)
	if err != nil {
		return fmt.Errorf("insert monitor_event: %w", err)
	}

	return nil
}

// UpdateEventWebhookStatus updates the webhook status of an event.
func (r *MonitorRepository) UpdateEventWebhookStatus(ctx context.Context, eventID uuid.UUID, status WebhookStatus, attempts int, lastError *string, sentAt *time.Time) error {
	_, err := r.db.pool.Exec(ctx, `
		UPDATE monitor_events
		SET webhook_status = $2, webhook_attempts = $3, webhook_last_error = $4, sent_at = $5
		WHERE id = $1
	`, eventID, status, attempts, lastError, sentAt)
	if err != nil {
		return fmt.Errorf("update monitor_event webhook status: %w", err)
	}

	return nil
}

// GetPendingEvents retrieves events with pending webhook status.
func (r *MonitorRepository) GetPendingEvents(ctx context.Context, limit int) ([]*MonitorEvent, error) {
	rows, err := r.db.pool.Query(ctx, `
		SELECT id, monitor_id, event_type, payload, webhook_status, webhook_attempts, webhook_last_error, created_at, sent_at
		FROM monitor_events
		WHERE webhook_status = $1
		ORDER BY created_at
		LIMIT $2
	`, WebhookStatusPending, limit)
	if err != nil {
		return nil, fmt.Errorf("query pending events: %w", err)
	}
	defer rows.Close()

	var events []*MonitorEvent
	for rows.Next() {
		var event MonitorEvent
		if err := rows.Scan(
			&event.ID,
			&event.MonitorID,
			&event.EventType,
			&event.Payload,
			&event.WebhookStatus,
			&event.WebhookAttempts,
			&event.WebhookLastError,
			&event.CreatedAt,
			&event.SentAt,
		); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		events = append(events, &event)
	}

	return events, nil
}

// CountActiveMonitors returns the count of active monitors.
func (r *MonitorRepository) CountActiveMonitors(ctx context.Context) (int, error) {
	var count int
	err := r.db.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM monitors WHERE status IN ($1, $2, $3)
	`, StatusInitializing, StatusWaiting, StatusMonitoring).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active monitors: %w", err)
	}
	return count, nil
}

// ErrMonitorNotActive is returned when trying to update a non-active monitor.
var ErrMonitorNotActive = errors.New("monitor is not in an active state")

// UpdateMonitorParams contains parameters for updating a monitor.
type UpdateMonitorParams struct {
	CallbackURL *string
	Config      *MonitorConfig
}

// UpdateMonitor updates an active monitor's callback_url and/or config.
func (r *MonitorRepository) UpdateMonitor(ctx context.Context, id string, params UpdateMonitorParams) (*Monitor, error) {
	// Build dynamic SET clause
	setClauses := []string{"updated_at = NOW()"}
	var args []interface{}
	argIdx := 1

	args = append(args, id)
	argIdx++

	if params.CallbackURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("callback_url = $%d", argIdx))
		args = append(args, *params.CallbackURL)
		argIdx++
	}

	if params.Config != nil {
		configJSON, err := json.Marshal(params.Config)
		if err != nil {
			return nil, fmt.Errorf("marshal config: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("config = $%d", argIdx))
		args = append(args, configJSON)
		argIdx++
	}

	// Parameterize status constants instead of interpolating them
	statusPlaceholders := fmt.Sprintf("$%d, $%d, $%d", argIdx, argIdx+1, argIdx+2)
	args = append(args, StatusInitializing, StatusWaiting, StatusMonitoring)

	query := fmt.Sprintf(`
		UPDATE monitors
		SET %s
		WHERE id = $1 AND status IN (%s)
		RETURNING id, stream_url, callback_url, config, metadata, status, pod_name, created_at, updated_at
	`, strings.Join(setClauses, ", "), statusPlaceholders)

	var monitor Monitor
	var configJSON []byte

	err := r.db.pool.QueryRow(ctx, query, args...).Scan(
		&monitor.ID,
		&monitor.StreamURL,
		&monitor.CallbackURL,
		&configJSON,
		&monitor.Metadata,
		&monitor.Status,
		&monitor.PodName,
		&monitor.CreatedAt,
		&monitor.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Check if the monitor exists but is not active
			_, getErr := r.GetByID(ctx, id)
			if getErr != nil {
				if errors.Is(getErr, ErrMonitorNotFound) {
					return nil, ErrMonitorNotFound
				}
				return nil, getErr
			}
			return nil, ErrMonitorNotActive
		}
		return nil, fmt.Errorf("update monitor: %w", err)
	}

	if err := json.Unmarshal(configJSON, &monitor.Config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &monitor, nil
}

// ListEventsParams contains parameters for listing events.
type ListEventsParams struct {
	Limit  int
	Offset int
}

// ListEvents retrieves events for a monitor with pagination.
func (r *MonitorRepository) ListEvents(ctx context.Context, monitorID string, params ListEventsParams) ([]*MonitorEvent, int, error) {
	if params.Limit <= 0 {
		params.Limit = 50
	}
	if params.Limit > 100 {
		params.Limit = 100
	}

	// Count total
	var total int
	err := r.db.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM monitor_events WHERE monitor_id = $1
	`, monitorID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count events: %w", err)
	}

	// Fetch events
	rows, err := r.db.pool.Query(ctx, `
		SELECT id, monitor_id, event_type, payload, webhook_status, webhook_attempts, webhook_last_error, created_at, sent_at
		FROM monitor_events
		WHERE monitor_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`, monitorID, params.Limit, params.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []*MonitorEvent
	for rows.Next() {
		var event MonitorEvent
		if err := rows.Scan(
			&event.ID,
			&event.MonitorID,
			&event.EventType,
			&event.Payload,
			&event.WebhookStatus,
			&event.WebhookAttempts,
			&event.WebhookLastError,
			&event.CreatedAt,
			&event.SentAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan event: %w", err)
		}
		events = append(events, &event)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate events: %w", err)
	}

	return events, total, nil
}

// DeleteStaleMonitors deletes monitors in terminal states older than the given time.
func (r *MonitorRepository) DeleteStaleMonitors(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := r.db.pool.Exec(ctx, `
		DELETE FROM monitors
		WHERE status IN ($1, $2, $3) AND updated_at < $4
	`, StatusCompleted, StatusStopped, StatusError, olderThan)
	if err != nil {
		return 0, fmt.Errorf("delete stale monitors: %w", err)
	}

	return result.RowsAffected(), nil
}

func isDuplicateKeyError(err error) bool {
	// pgx v5 returns errors with SQLSTATE
	return err != nil && (strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "duplicate key"))
}
