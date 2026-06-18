package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

const maxBodySize = 1 * 1024 * 1024 // 1MB

var db *DB

var rateLimiter = NewRateLimiter()

var (
	requestCount    atomic.Uint64
	requestErrors   atomic.Uint64
	requestDuration atomic.Uint64
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type RateLimiter struct {
	mu      sync.RWMutex
	windows map[string]*rateWindow
}

type rateWindow struct {
	count      int
	resetAt    time.Time
	blocked    bool
	blockUntil time.Time
}

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		windows: make(map[string]*rateWindow),
	}
	go func() {
		for {
			time.Sleep(time.Minute)
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for key, window := range rl.windows {
		if now.After(window.resetAt) && !window.blocked {
			delete(rl.windows, key)
		} else if window.blocked && now.After(window.blockUntil) {
			delete(rl.windows, key)
		}
	}
}

func (rl *RateLimiter) checkLimit(key string, maxRequests int, windowDuration time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	window, exists := rl.windows[key]

	if !exists || now.After(window.resetAt) {
		rl.windows[key] = &rateWindow{
			count:   1,
			resetAt: now.Add(windowDuration),
		}
		return true
	}

	if window.blocked {
		return false
	}

	if window.count >= maxRequests {
		window.blocked = true
		window.blockUntil = now.Add(windowDuration)
		return false
	}

	window.count++
	return true
}

func (rl *RateLimiter) increment(key string, maxRequests int, windowDuration time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	window, exists := rl.windows[key]

	if !exists || now.After(window.resetAt) {
		rl.windows[key] = &rateWindow{
			count:   1,
			resetAt: now.Add(windowDuration),
		}
		return
	}

	window.count++
	if window.count >= maxRequests {
		window.blocked = true
		window.blockUntil = now.Add(windowDuration)
	}
}

func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.windows = make(map[string]*rateWindow)
}

func (rl *RateLimiter) isBlocked(key string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	window, exists := rl.windows[key]
	if !exists {
		return false
	}
	return window.blocked && time.Now().Before(window.blockUntil)
}

func getIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	if idx := len(ip) - 1; idx > 0 {
		for i := idx; i >= 0; i-- {
			if ip[i] == ':' {
				ip = ip[:i]
				break
			}
		}
	}
	return ip
}

func extractBearerToken(authHeader string) string {
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	return ""
}

func isValidEmail(email string) bool {
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}

func isValidAPIKey(key string) bool {
	_, err := uuid.Parse(key)
	return err == nil
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

func main() {
	godotenv.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := runServer(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func runServer() error {
	var err error

	db, err = InitDB()
	if err != nil {
		return fmt.Errorf("failed to init DB: %w", err)
	}

	mux := http.NewServeMux()

	// Static files
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/", fs)
	mux.Handle("/privacy.html", fs)
	mux.Handle("/openapi.yaml", http.FileServer(http.Dir(".")))

	// API routes
	mux.HandleFunc("GET /health", rateLimitHandler(healthHandler, "health", 60, time.Minute))
	mux.HandleFunc("GET /metrics", adminAuth(rateLimitHandler(metricsHandler, "metrics", 30, time.Minute)))
	mux.HandleFunc("POST /v1/signup", rateLimitHandler(bodyLimitHandler(signupHandler), "signup", 3, time.Hour))
	mux.HandleFunc("GET /v1/users/{id}", rateLimitHandler(getUserHandler, "user", 100, time.Minute))
	mux.HandleFunc("POST /v1/login", rateLimitFailedLogin(bodyLimitHandler(loginHandler)))
	mux.HandleFunc("POST /v1/uuid", rateLimitByAPIKey(bodyLimitHandler(generateUUIDHandler), "uuid", 100, time.Minute))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Apply global rate limit + logging to everything
	wrapped := loggingMiddleware(globalRateLimit(mux))

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      wrapped,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	slog.Info("server starting", "addr", srv.Addr)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen error", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("server shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return srv.Shutdown(ctx)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := uuid.New().String()

		w.Header().Set("X-Request-ID", reqID)

		rw := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		requestCount.Add(1)
		requestDuration.Add(uint64(duration.Nanoseconds()))
		if rw.statusCode >= 400 {
			requestErrors.Add(1)
		}

		slog.Info("request",
			"request_id", reqID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration_ms", duration.Milliseconds(),
			"ip", getIP(r),
		)
	})
}

// Global per-IP rate limit: 1000 requests/hour across all endpoints
func globalRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		key := ip + ":global"
		if !rateLimiter.checkLimit(key, 1000, time.Hour) {
			writeError(w, http.StatusTooManyRequests, "global_rate_limit_exceeded", "Too many requests from this IP. Please try again later.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Body size limit middleware
func bodyLimitHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		next(w, r)
	}
}

// Admin auth middleware for sensitive endpoints
func adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adminKey := os.Getenv("ADMIN_API_KEY")
		if adminKey == "" {
			// If no admin key is set, allow access (for dev convenience)
			next(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+adminKey {
			writeError(w, http.StatusUnauthorized, "admin_required", "Admin authentication required")
			return
		}
		next(w, r)
	}
}

func rateLimitHandler(next http.HandlerFunc, limitKey string, maxRequests int, windowDuration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := getIP(r) + ":" + limitKey
		if !rateLimiter.checkLimit(key, maxRequests, windowDuration) {
			writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Rate limit exceeded. Please try again later.")
			return
		}
		next(w, r)
	}
}

func rateLimitByAPIKey(next http.HandlerFunc, limitKey string, maxRequests int, windowDuration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := extractBearerToken(r.Header.Get("Authorization"))
		if apiKey == "" {
			writeError(w, http.StatusUnauthorized, "authorization_required", "Authorization header is required")
			return
		}
		if !isValidAPIKey(apiKey) {
			writeError(w, http.StatusUnauthorized, "invalid_api_key_format", "Invalid API key format")
			return
		}
		key := "apikey:" + apiKey + ":" + limitKey
		if !rateLimiter.checkLimit(key, maxRequests, windowDuration) {
			writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Rate limit exceeded. Please try again later.")
			return
		}
		next(w, r)
	}
}

func rateLimitFailedLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		failedKey := ip + ":failed_login"

		if rateLimiter.isBlocked(failedKey) {
			writeError(w, http.StatusTooManyRequests, "too_many_failed_logins", "Too many failed login attempts. Please try again later.")
			return
		}

		rw := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next(rw, r)

		if rw.statusCode == http.StatusUnauthorized {
			rateLimiter.increment(failedKey, 10, time.Minute)
		}
	}
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.statusCode = code
	sr.ResponseWriter.WriteHeader(code)
}

type CreateUserRequest struct {
	Email string `json:"email"`
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

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	count := requestCount.Load()
	var avgDuration float64
	if count > 0 {
		avgDuration = float64(requestDuration.Load()) / float64(count) / 1e6
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"requests_total":  count,
		"requests_errors": requestErrors.Load(),
		"avg_duration_ms": avgDuration,
	})
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON in request body")
		return
	}

	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "email_required", "Email is required")
		return
	}

	if !isValidEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "invalid_email", "Invalid email format")
		return
	}

	if len(req.Email) > 254 {
		writeError(w, http.StatusBadRequest, "email_too_long", "Email must be less than 254 characters")
		return
	}

	plaintextKey := uuid.New().String()
	id, err := db.CreateUser(req.Email, plaintextKey)
	if err != nil {
		if dbErr, ok := err.(DBError); ok {
			if dbErr.Code == "email_exists" {
				writeError(w, http.StatusConflict, dbErr.Code, dbErr.Message)
				return
			}
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to create user")
		return
	}

	user, err := db.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve user")
		return
	}

	resp := CreateUserResponse{
		ID:     user.ID,
		Email:  user.Email,
		APIKey: plaintextKey,
		Status: user.Status,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	apiKey := extractBearerToken(authHeader)

	if apiKey == "" {
		writeError(w, http.StatusUnauthorized, "authorization_required", "Authorization header is required")
		return
	}

	if !isValidAPIKey(apiKey) {
		writeError(w, http.StatusUnauthorized, "invalid_api_key_format", "Invalid API key format")
		return
	}

	user, err := db.GetUserByAPIKey(apiKey)
	if err != nil {
		if dbErr, ok := err.(DBError); ok && dbErr.Code == "invalid_api_key" {
			writeError(w, http.StatusUnauthorized, dbErr.Code, dbErr.Message)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve user")
		return
	}

	idStr := r.PathValue("id")
	var id int64
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_user_id", "Invalid user ID format")
		return
	}

	if user.ID != id {
		writeError(w, http.StatusNotFound, "user_not_found", "User not found")
		return
	}

	resp := UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Status:    user.Status,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	apiKey := extractBearerToken(authHeader)

	if apiKey == "" {
		writeError(w, http.StatusUnauthorized, "authorization_required", "Authorization header is required")
		return
	}

	if !isValidAPIKey(apiKey) {
		writeError(w, http.StatusUnauthorized, "invalid_api_key_format", "Invalid API key format")
		return
	}

	user, err := db.GetUserByAPIKey(apiKey)
	if err != nil {
		if dbErr, ok := err.(DBError); ok && dbErr.Code == "invalid_api_key" {
			writeError(w, http.StatusUnauthorized, dbErr.Code, dbErr.Message)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to authenticate")
		return
	}

	resp := UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Status:    user.Status,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func generateUUIDHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	apiKey := extractBearerToken(authHeader)

	if apiKey == "" {
		writeError(w, http.StatusUnauthorized, "authorization_required", "Authorization header is required")
		return
	}

	if !isValidAPIKey(apiKey) {
		writeError(w, http.StatusUnauthorized, "invalid_api_key_format", "Invalid API key format")
		return
	}

	user, err := db.GetUserByAPIKey(apiKey)
	if err != nil {
		if dbErr, ok := err.(DBError); ok && dbErr.Code == "invalid_api_key" {
			writeError(w, http.StatusUnauthorized, dbErr.Code, dbErr.Message)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to authenticate")
		return
	}

	u := uuid.New().String()

	if err := db.CreateUUIDRecord(u, user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to store UUID")
		return
	}

	resp := UUIDResponse{
		UUID:      u,
		UserID:    user.ID,
		Email:     user.Email,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
