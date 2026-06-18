package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

type DB struct {
	*sql.DB
}

func InitDB() (*DB, error) {
	tursoURL := os.Getenv("TURSO_DATABASE_URL")
	if tursoURL == "" {
		return nil, fmt.Errorf("TURSO_DATABASE_URL environment variable is required")
	}

	authToken := os.Getenv("TURSO_AUTH_TOKEN")
	if authToken != "" {
		tursoURL = tursoURL + "?authToken=" + authToken
	}

	var db *sql.DB
	var err error

	// Retry connection with exponential backoff
	for attempt := 1; attempt <= 5; attempt++ {
		db, err = sql.Open("libsql", tursoURL)
		if err == nil {
			err = db.Ping()
		}
		if err == nil {
			break
		}
		slog.Warn("db connection failed, retrying", "attempt", attempt, "error", err)
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libsql database after retries: %w", err)
	}

	// Connection pooling
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := createTables(db); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return &DB{db}, nil
}

func createTables(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		api_key TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS uuids (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		uuid TEXT NOT NULL UNIQUE,
		user_id INTEGER NOT NULL,
		created_at TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
	CREATE INDEX IF NOT EXISTS idx_uuids_user_id ON uuids(user_id);
	`

	_, err := db.Exec(schema)
	return err
}

type User struct {
	ID        int64
	Email     string
	APIKey    string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (db *DB) CreateUser(email, apiKey string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	keyHash := hashAPIKey(apiKey)

	result, err := db.Exec(
		"INSERT INTO users (email, api_key, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		email, keyHash, "active", now, now,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (db *DB) GetUserByID(id int64) (*User, error) {
	var user User
	var createdAt, updatedAt string
	err := db.QueryRow(
		"SELECT id, email, api_key, status, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Email, &user.APIKey, &user.Status, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	user.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &user, nil
}

func (db *DB) GetUserByAPIKey(apiKey string) (*User, error) {
	keyHash := hashAPIKey(apiKey)

	var user User
	var createdAt, updatedAt string
	err := db.QueryRow(
		"SELECT id, email, api_key, status, created_at, updated_at FROM users WHERE api_key = ? AND status = 'active'",
		keyHash,
	).Scan(&user.ID, &user.Email, &user.APIKey, &user.Status, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	user.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &user, nil
}

func (db *DB) CreateUUIDRecord(uuid string, userID int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(
		"INSERT INTO uuids (uuid, user_id, created_at) VALUES (?, ?, ?)",
		uuid, userID, now,
	)
	return err
}

func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}
