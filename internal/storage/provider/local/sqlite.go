package local

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
	"github.com/nckslvrmn/whisper/pkg/utils"
)

type SQLiteStore struct {
	db        *sql.DB
	fileStore storagetypes.FileStore
}

func NewSQLiteStore(dataDir string, fileStore storagetypes.FileStore) (storagetypes.SecretStore, error) {
	dbPath := filepath.Join(dataDir, "secrets.db")

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &SQLiteStore{
		db:        db,
		fileStore: fileStore,
	}

	if err := store.createTable(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	go func() {
		for {
			time.Sleep(1 * time.Hour)
			if rowsAffected, err := store.cleanupExpiredSecrets(); err != nil {
				log.Printf("Warning: failed to cleanup expired secrets: %v", err)
			} else {
				log.Printf("Successfully cleaned up %d expired secrets", rowsAffected)
			}
		}
	}()

	log.Printf("SQLite store initialized at %s", dbPath)
	return store, nil
}

func (s *SQLiteStore) createTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS secrets (
		secret_id TEXT PRIMARY KEY,
		data TEXT NOT NULL,
		view_count INTEGER NOT NULL,
		ttl INTEGER NOT NULL,
		created_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_ttl ON secrets(ttl);
	`

	_, err := s.db.Exec(query)
	return err
}

func (s *SQLiteStore) StoreSecretRaw(secretId string, data []byte, ttl int64, viewCount int) error {
	query := `
		INSERT INTO secrets (secret_id, data, view_count, ttl, created_at)
		VALUES (?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(
		query,
		secretId,
		utils.B64E(data),
		viewCount,
		ttl,
		time.Now().Unix(),
	)

	if err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	return nil
}

func (s *SQLiteStore) GetSecretRaw(secretId string) ([]byte, error) {
	query := `SELECT data FROM secrets WHERE secret_id = ?`

	var encodedData string
	err := s.db.QueryRow(query, secretId).Scan(&encodedData)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("secret not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	data, err := utils.B64D(encodedData)
	if err != nil {
		return nil, fmt.Errorf("invalid data encoding: %w", err)
	}

	return data, nil
}

func (s *SQLiteStore) UpdateSecretRaw(secretId string, data []byte) error {
	query := `UPDATE secrets SET data = ? WHERE secret_id = ?`

	result, err := s.db.Exec(query, utils.B64E(data), secretId)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("secret not found")
	}

	return nil
}

func (s *SQLiteStore) DeleteSecret(secretId string) error {
	query := `DELETE FROM secrets WHERE secret_id = ?`

	_, err := s.db.Exec(query, secretId)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}

func (s *SQLiteStore) cleanupExpiredSecrets() (int64, error) {
	query := `DELETE FROM secrets WHERE ttl < ? RETURNING secret_id`

	rows, err := s.db.Query(query, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired secrets: %w", err)
	}
	defer rows.Close()

	var count int64
	for rows.Next() {
		var secretId string
		if err := rows.Scan(&secretId); err != nil {
			log.Printf("Warning: failed to scan secret_id during cleanup: %v", err)
			continue
		}

		if s.fileStore != nil {
			if err := s.fileStore.DeleteEncryptedFile(secretId); err != nil {
				log.Printf("Warning: failed to delete encrypted file for secret %s: %v", secretId, err)
			}
		}
		count++
	}

	if err := rows.Err(); err != nil {
		return count, fmt.Errorf("error iterating rows: %w", err)
	}

	return count, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
