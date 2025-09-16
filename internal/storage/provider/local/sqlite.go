package local

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	storagetypes "github.com/nckslvrmn/secure_secret_share/internal/storage/types"
	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(dataDir string) (storagetypes.SecretStore, error) {
	dbPath := filepath.Join(dataDir, "secrets.db")

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &SQLiteStore{db: db}

	if err := store.createTable(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

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

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
