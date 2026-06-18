package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"valid bearer", "Bearer abc123", "abc123"},
		{"no bearer prefix", "abc123", ""},
		{"empty string", "", ""},
		{"bearer with spaces", "Bearer abc 123", "abc 123"},
		{"short string", "Bear", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBearerToken(tt.input)
			if result != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, result)
			}
		})
	}
}

func TestGetIP(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		remote  string
		expect  string
	}{
		{
			name:    "X-Forwarded-For",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4"},
			remote:  "192.168.1.1:1234",
			expect:  "1.2.3.4",
		},
		{
			name:    "X-Real-IP",
			headers: map[string]string{"X-Real-IP": "5.6.7.8"},
			remote:  "192.168.1.1:1234",
			expect:  "5.6.7.8",
		},
		{
			name:    "RemoteAddr",
			headers: map[string]string{},
			remote:  "192.168.1.1:1234",
			expect:  "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			req.RemoteAddr = tt.remote
			result := getIP(req)
			if result != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, result)
			}
		})
	}
}

func TestHashAPIKey(t *testing.T) {
	// Hash should be deterministic
	h1 := hashAPIKey("test-key")
	h2 := hashAPIKey("test-key")
	if h1 != h2 {
		t.Error("hashAPIKey should be deterministic")
	}

	// Different keys should produce different hashes
	h3 := hashAPIKey("different-key")
	if h1 == h3 {
		t.Error("different keys should produce different hashes")
	}

	// Should be 64 chars (hex encoded SHA256)
	if len(h1) != 64 {
		t.Errorf("expected hash length 64, got %d", len(h1))
	}
}

func TestRateLimiter_CheckLimit(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-key"

	// Should allow first 5 requests
	for i := 0; i < 5; i++ {
		if !rl.checkLimit(key, 5, time.Minute) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be blocked
	if rl.checkLimit(key, 5, time.Minute) {
		t.Error("6th request should be blocked")
	}
}

func TestRateLimiter_WindowReset(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-key"

	// Use a very short window
	if !rl.checkLimit(key, 1, 50*time.Millisecond) {
		t.Error("first request should be allowed")
	}

	// Should be blocked within window
	if rl.checkLimit(key, 1, 50*time.Millisecond) {
		t.Error("second request should be blocked")
	}

	// Wait for window to reset
	time.Sleep(100 * time.Millisecond)

	if !rl.checkLimit(key, 1, 50*time.Millisecond) {
		t.Error("request after window reset should be allowed")
	}
}

func TestRateLimiter_Increment(t *testing.T) {
	rl := NewRateLimiter()
	key := "failed-login"

	// Increment up to limit
	for i := 0; i < 3; i++ {
		rl.increment(key, 3, time.Minute)
	}

	// Should be blocked now
	if !rl.isBlocked(key) {
		t.Error("should be blocked after reaching limit")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-key"

	rl.checkLimit(key, 1, time.Minute)
	rl.checkLimit(key, 1, time.Minute) // blocked

	rl.Reset()

	if rl.isBlocked(key) {
		t.Error("reset should clear blocked status")
	}
}

func TestHealthHandler(t *testing.T) {
	// Health handler requires DB, skip for now
	t.Skip("requires database connection")
}

func TestMetricsHandler(t *testing.T) {
	srv := NewServer(nil)
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()

	srv.metricsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "requests_total") {
		t.Errorf("expected body to contain 'requests_total', got %s", body)
	}
}

func TestStatusRecorder(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, statusCode: http.StatusOK}

	sr.WriteHeader(http.StatusNotFound)
	if sr.statusCode != http.StatusNotFound {
		t.Errorf("expected status code %d, got %d", http.StatusNotFound, sr.statusCode)
	}
}
