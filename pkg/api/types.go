package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type CLIConfig struct {
	BaseURL  string `json:"base_url"`
	APIToken string `json:"api_token"`
	UserID   int64  `json:"user_id"`
}

type CreateUserResponse struct {
	ID     int64  `json:"id"`
	Email  string `json:"email"`
	APIKey string `json:"api_key"`
	Status string `json:"status"`
}

type UserResponse struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type UUIDResponse struct {
	UUID      string `json:"uuid"`
	UserID    int64  `json:"user_id"`
	Email     string `json:"email"`
	Timestamp string `json:"timestamp"`
}

func APIRequest(method, path string, body interface{}, cfg *CLIConfig) (*http.Response, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}
