package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func startTestServer(t *testing.T) string {
	// Reset rate limiter between tests
	rateLimiter.Reset()

	var err error
	db, err = InitDB()
	if err != nil {
		t.Fatalf("Failed to init test DB: %v", err)
	}

	// Create a new ServeMux for each test to avoid conflicts
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/signup", rateLimitHandler(signupHandler, "signup", 3, time.Hour))
	mux.HandleFunc("GET /v1/users/{id}", getUserHandler)
	mux.HandleFunc("POST /v1/login", rateLimitFailedLogin(loginHandler))
	mux.HandleFunc("POST /v1/uuid", rateLimitByAPIKey(generateUUIDHandler, "uuid", 100, time.Minute))

	// Start server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	addr := listener.Addr().String()

	server := &http.Server{Handler: mux}
	go func() {
		if err := server.Serve(listener); err != nil {
			// Server closed, expected
		}
	}()

	// Give server a moment to start
	time.Sleep(50 * time.Millisecond)

	return addr
}

func createTestUser(t *testing.T, baseURL, email string) CreateUserResponse {
	reqBody := fmt.Sprintf(`{"email":"%s"}`, email)
	resp, err := http.Post(baseURL+"/v1/signup", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	var user CreateUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	return user
}

func TestE2E_UserCreation(t *testing.T) {
	addr := startTestServer(t)
	baseURL := "http://" + addr

	user := createTestUser(t, baseURL, "test@example.com")

	if user.Email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", user.Email)
	}
	if user.APIKey == "" {
		t.Error("Expected non-empty API key")
	}
	if user.ID == 0 {
		t.Error("Expected non-zero ID")
	}
}

func TestE2E_UUIDGeneration(t *testing.T) {
	addr := startTestServer(t)
	baseURL := "http://" + addr

	user := createTestUser(t, baseURL, "uuidtest@example.com")

	// Try without auth
	resp, err := http.Post(baseURL+"/v1/uuid", "application/json", nil)
	if err != nil {
		t.Fatalf("Failed to generate UUID: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected status 401 without auth, got %d", resp.StatusCode)
	}

	// Generate UUID with auth
	req, _ := http.NewRequest("POST", baseURL+"/v1/uuid", nil)
	req.Header.Set("Authorization", "Bearer "+user.APIKey)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to generate UUID with auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	var uuidResp UUIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&uuidResp); err != nil {
		t.Fatalf("Failed to decode UUID response: %v", err)
	}

	if uuidResp.UUID == "" {
		t.Error("Expected non-empty UUID")
	}
	if uuidResp.UserID != user.ID {
		t.Errorf("Expected user ID %d, got %d", user.ID, uuidResp.UserID)
	}
	if uuidResp.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, uuidResp.Email)
	}
}

func TestE2E_UUIDUniqueness(t *testing.T) {
	addr := startTestServer(t)
	baseURL := "http://" + addr

	user := createTestUser(t, baseURL, "unique@example.com")

	// Generate multiple UUIDs
	uuids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("POST", baseURL+"/v1/uuid", nil)
		req.Header.Set("Authorization", "Bearer "+user.APIKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to generate UUID: %v", err)
		}

		var uuidResp UUIDResponse
		if err := json.NewDecoder(resp.Body).Decode(&uuidResp); err != nil {
			resp.Body.Close()
			t.Fatalf("Failed to decode UUID response: %v", err)
		}
		resp.Body.Close()

		if uuidResp.UUID == "" {
			t.Fatalf("Empty UUID generated on attempt %d", i)
		}
		if uuids[uuidResp.UUID] {
			t.Fatalf("Duplicate UUID generated: %s", uuidResp.UUID)
		}
		uuids[uuidResp.UUID] = true
	}
}

func TestE2E_GetUser(t *testing.T) {
	addr := startTestServer(t)
	baseURL := "http://" + addr

	user := createTestUser(t, baseURL, "getuser@example.com")

	// Get user without auth
	resp, err := http.Get(fmt.Sprintf("%s/users/%d", baseURL, user.ID))
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected status 401 without auth, got %d", resp.StatusCode)
	}

	// Get user with auth
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/users/%d", baseURL, user.ID), nil)
	req.Header.Set("Authorization", "Bearer "+user.APIKey)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to get user with auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	var fetchedUser UserResponse
	if err := json.NewDecoder(resp.Body).Decode(&fetchedUser); err != nil {
		t.Fatalf("Failed to decode user: %v", err)
	}

	if fetchedUser.ID != user.ID {
		t.Errorf("Expected ID %d, got %d", user.ID, fetchedUser.ID)
	}
	if fetchedUser.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, fetchedUser.Email)
	}
}

func TestE2E_Login(t *testing.T) {
	addr := startTestServer(t)
	baseURL := "http://" + addr

	user := createTestUser(t, baseURL, "login@example.com")

	// Login without auth
	resp, err := http.Post(baseURL+"/v1/login", "application/json", nil)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected status 401 without auth, got %d", resp.StatusCode)
	}

	// Login with auth
	req, _ := http.NewRequest("POST", baseURL+"/v1/login", nil)
	req.Header.Set("Authorization", "Bearer "+user.APIKey)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to login with auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	var loginResp UserResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}

	if loginResp.ID != user.ID {
		t.Errorf("Expected ID %d, got %d", user.ID, loginResp.ID)
	}
	if loginResp.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, loginResp.Email)
	}
}

func TestE2E_InvalidUserID(t *testing.T) {
	addr := startTestServer(t)
	baseURL := "http://" + addr

	user := createTestUser(t, baseURL, "invalid@example.com")

	req, _ := http.NewRequest("GET", baseURL+"/v1/users/99999", nil)
	req.Header.Set("Authorization", "Bearer "+user.APIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

func TestE2E_RateLimitUUID(t *testing.T) {
	addr := startTestServer(t)
	baseURL := "http://" + addr

	user := createTestUser(t, baseURL, "ratelimit@example.com")

	// Generate UUIDs until rate limit
	for i := 0; i < 100; i++ {
		req, _ := http.NewRequest("POST", baseURL+"/v1/uuid", nil)
		req.Header.Set("Authorization", "Bearer "+user.APIKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to generate UUID: %v", err)
		}
		resp.Body.Close()
	}

	// Next request should be rate limited
	req, _ := http.NewRequest("POST", baseURL+"/v1/uuid", nil)
	req.Header.Set("Authorization", "Bearer "+user.APIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to generate UUID: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", resp.StatusCode)
	}
}

func TestE2E_RateLimitSignup(t *testing.T) {
	addr := startTestServer(t)
	baseURL := "http://" + addr

	// Create 3 users (should work)
	for i := 0; i < 3; i++ {
		reqBody := fmt.Sprintf(`{"email":"signup%d@example.com"}`, i)
		resp, err := http.Post(baseURL+"/v1/signup", "application/json", strings.NewReader(reqBody))
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for signup %d, got %d", i, resp.StatusCode)
		}
	}

	// 4th signup should be rate limited
	reqBody := `{"email":"signup4@example.com"}`
	resp, err := http.Post(baseURL+"/v1/signup", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", resp.StatusCode)
	}
}

func TestE2E_RateLimitFailedLogin(t *testing.T) {
	addr := startTestServer(t)
	baseURL := "http://" + addr

	// Make 10 failed login attempts
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("POST", baseURL+"/v1/login", nil)
		req.Header.Set("Authorization", "Bearer invalid-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to login: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for attempt %d, got %d", i, resp.StatusCode)
		}
	}

	// 11th attempt should be rate limited
	req, _ := http.NewRequest("POST", baseURL+"/v1/login", nil)
	req.Header.Set("Authorization", "Bearer invalid-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", resp.StatusCode)
	}
}

func TestMain(m *testing.M) {
	// Run tests
	os.Exit(m.Run())
}
