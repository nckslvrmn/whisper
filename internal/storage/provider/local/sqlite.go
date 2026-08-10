package local

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
)

const janitorInterval = 1 * time.Hour

type SQLiteStore struct {
	db        *sql.DB
	fileStore storagetypes.FileStore
	done      chan struct{}
}

func NewSQLiteStore(dataDir string, fileStore storagetypes.FileStore) (storagetypes.SecretStore, error) {
	dbPath := filepath.Join(dataDir, "secrets.db")

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	// Serializing all access keeps the ConsumeView transaction from ever
	// competing with itself for the write lock and hitting SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	store := &SQLiteStore{
		db:        db,
		fileStore: fileStore,
		done:      make(chan struct{}),
	}

	if err := store.createTable(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	go store.janitor(janitorInterval)

	log.Printf("SQLite store initialized at %s", dbPath)
	return store, nil
}

func (s *SQLiteStore) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if rowsAffected, err := s.cleanupExpiredSecrets(context.Background()); err != nil {
				log.Printf("Warning: failed to cleanup expired secrets: %v", err)
			} else {
				log.Printf("Successfully cleaned up %d expired secrets", rowsAffected)
			}
		}
	}
}

func (s *SQLiteStore) createTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS secrets (
		secret_id TEXT PRIMARY KEY,
		data TEXT NOT NULL,
		view_count INTEGER,
		ttl INTEGER,
		created_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_ttl ON secrets(ttl) WHERE ttl IS NOT NULL;
	`

	_, err := s.db.Exec(query)
	return err
}

func (s *SQLiteStore) StoreSecret(ctx context.Context, id string, payload []byte, ttl *int64, viewCount *int) error {
	query := `
		INSERT INTO secrets (secret_id, data, view_count, ttl, created_at)
		VALUES (?, ?, ?, ?, ?)
	`

	var ttlValue any
	if ttl != nil {
		ttlValue = *ttl
	}

	var viewCountValue any
	if viewCount != nil && *viewCount > 0 {
		viewCountValue = *viewCount
	}

	_, err := s.db.ExecContext(ctx, query, id, string(payload), viewCountValue, ttlValue, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	return nil
}

func (s *SQLiteStore) GetSecret(ctx context.Context, id string) ([]byte, *int64, error) {
	var stored string
	var ttl sql.NullInt64

	err := s.db.QueryRowContext(ctx, `SELECT data, ttl FROM secrets WHERE secret_id = ?`, id).Scan(&stored, &ttl)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, storagetypes.ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get secret: %w", err)
	}

	payload, err := storagetypes.DecodeStoredPayload(stored)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid data encoding: %w", err)
	}

	if !ttl.Valid {
		return payload, nil, nil
	}
	return payload, &ttl.Int64, nil
}

func (s *SQLiteStore) ConsumeView(ctx context.Context, id string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var remaining int
	err = tx.QueryRowContext(
		ctx,
		`UPDATE secrets SET view_count = view_count - 1 WHERE secret_id = ? AND view_count > 0 RETURNING view_count`,
		id,
	).Scan(&remaining)

	switch {
	case err == nil:
		if remaining == 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM secrets WHERE secret_id = ?`, id); err != nil {
				return 0, fmt.Errorf("failed to delete exhausted secret: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("failed to commit view consumption: %w", err)
		}
		return remaining, nil

	case errors.Is(err, sql.ErrNoRows):
		// Either the row is gone or its counter is NULL/0, which both mean
		// unlimited: no new write ever leaves a 0 behind.
		var viewCount sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT view_count FROM secrets WHERE secret_id = ?`, id).Scan(&viewCount)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, storagetypes.ErrNotFound
		}
		if err != nil {
			return 0, fmt.Errorf("failed to read view count: %w", err)
		}
		return storagetypes.UnlimitedViews, nil

	default:
		return 0, fmt.Errorf("failed to consume view: %w", err)
	}
}

func (s *SQLiteStore) DeleteSecret(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE secret_id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}

func (s *SQLiteStore) cleanupExpiredSecrets(ctx context.Context) (int64, error) {
	query := `DELETE FROM secrets WHERE ttl IS NOT NULL AND ttl < ? RETURNING secret_id`

	rows, err := s.db.QueryContext(ctx, query, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired secrets: %w", err)
	}
	defer rows.Close()

	var expired []string
	for rows.Next() {
		var secretId string
		if err := rows.Scan(&secretId); err != nil {
			log.Printf("Warning: failed to scan secret_id during cleanup: %v", err)
			continue
		}
		expired = append(expired, secretId)
	}
	if err := rows.Err(); err != nil {
		return int64(len(expired)), fmt.Errorf("error iterating rows: %w", err)
	}
	rows.Close()

	if s.fileStore != nil {
		for _, secretId := range expired {
			if err := s.fileStore.DeleteEncryptedFile(ctx, secretId); err != nil {
				log.Printf("Warning: failed to delete encrypted file for secret %s: %v", secretId, err)
			}
		}
	}

	return int64(len(expired)), nil
}

func (s *SQLiteStore) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return s.db.Close()
}
