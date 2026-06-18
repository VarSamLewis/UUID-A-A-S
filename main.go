package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

const (
	maxBodySize         = 1 * 1024 * 1024 // 1MB
	defaultPort         = "8080"
	defaultReadTimeout  = 10 * time.Second
	defaultWriteTimeout = 10 * time.Second
	defaultIdleTimeout  = 120 * time.Second
	shutdownTimeout     = 10 * time.Second

	// Rate limits
	signupLimit     = 3
	signupWindow    = time.Hour
	uuidLimit       = 100
	uuidWindow      = time.Minute
	loginFailLimit  = 10
	loginFailWindow = time.Minute
	healthLimit     = 60
	healthWindow    = time.Minute
	metricsLimit    = 30
	metricsWindow   = time.Minute
	userGetLimit    = 100
	userGetWindow   = time.Minute
	globalIPLimit   = 1000
	globalIPWindow  = time.Hour

	// DB connection pool
	dbMaxOpenConns    = 25
	dbMaxIdleConns    = 5
	dbConnMaxLifetime = 5 * time.Minute

	// Retry config
	uuidCollisionRetries = 5
	dbConnectRetries     = 5
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type Server struct {
	db              *DB
	rateLimiter     *RateLimiter
	adminKey        string
	requestCount    atomic.Uint64
	requestErrors   atomic.Uint64
	requestDuration atomic.Uint64 // nanoseconds
}

func NewServer(db *DB) *Server {
	return &Server{
		db:          db,
		rateLimiter: NewRateLimiter(),
		adminKey:    os.Getenv("ADMIN_API_KEY"),
	}
}

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
	// Handle IPv4:port and IPv6 [addr]:port
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		return host
	}
	return ip
}

func extractBearerToken(authHeader string) string {
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	return ""
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
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

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func main() {
	godotenv.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	db, err := InitDB()
	if err != nil {
		return fmt.Errorf("failed to init DB: %w", err)
	}
	defer db.Close()

	srv := NewServer(db)
	return srv.runServer()
}

func (s *Server) runServer() error {
	mux := http.NewServeMux()

	// Static files - only serve specific files
	mux.HandleFunc("GET /{$}", s.serveStatic("static/index.html"))
	mux.HandleFunc("GET /privacy.html", s.serveStatic("static/privacy.html"))
	mux.HandleFunc("GET /openapi.yaml", s.serveStatic("openapi.yaml"))

	// API routes
	mux.HandleFunc("GET /health", s.rateLimit(s.healthHandler, "health", healthLimit, healthWindow))
	mux.HandleFunc("GET /metrics", s.adminAuth(s.rateLimit(s.metricsHandler, "metrics", metricsLimit, metricsWindow)))
	mux.HandleFunc("POST /v1/signup", s.rateLimit(s.bodyLimit(s.signupHandler), "signup", signupLimit, signupWindow))
	mux.HandleFunc("GET /v1/users/{id}", s.rateLimit(s.getUserHandler, "user", userGetLimit, userGetWindow))
	mux.HandleFunc("POST /v1/login", s.rateLimitFailedLogin(s.bodyLimit(s.loginHandler)))
	mux.HandleFunc("POST /v1/uuid", s.rateLimitByAPIKey(s.bodyLimit(s.generateUUIDHandler), "uuid", uuidLimit, uuidWindow))

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	wrapped := s.loggingMiddleware(s.globalRateLimit(mux))

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      wrapped,
		ReadTimeout:  defaultReadTimeout,
		WriteTimeout: defaultWriteTimeout,
		IdleTimeout:  defaultIdleTimeout,
	}

	slog.Info("server starting", "addr", server.Addr)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen error", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("server shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	return server.Shutdown(ctx)
}

func (s *Server) serveStatic(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path)
	}
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := uuid.New().String()

		w.Header().Set("X-Request-ID", reqID)

		rw := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		s.requestCount.Add(1)
		s.requestDuration.Add(uint64(duration.Nanoseconds()))
		if rw.statusCode >= 400 {
			s.requestErrors.Add(1)
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

func (s *Server) globalRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		key := ip + ":global"
		if !s.rateLimiter.checkLimit(key, globalIPLimit, globalIPWindow) {
			writeError(w, http.StatusTooManyRequests, "global_rate_limit_exceeded", "Too many requests from this IP. Please try again later.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) bodyLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		next(w, r)
	}
}

func (s *Server) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminKey == "" {
			writeError(w, http.StatusServiceUnavailable, "admin_not_configured", "Admin access is not configured")
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+s.adminKey {
			writeError(w, http.StatusUnauthorized, "admin_required", "Admin authentication required")
			return
		}
		next(w, r)
	}
}

func (s *Server) rateLimit(next http.HandlerFunc, limitKey string, maxRequests int, windowDuration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := getIP(r) + ":" + limitKey
		if !s.rateLimiter.checkLimit(key, maxRequests, windowDuration) {
			writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Rate limit exceeded. Please try again later.")
			return
		}
		next(w, r)
	}
}

func (s *Server) rateLimitByAPIKey(next http.HandlerFunc, limitKey string, maxRequests int, windowDuration time.Duration) http.HandlerFunc {
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
		if !s.rateLimiter.checkLimit(key, maxRequests, windowDuration) {
			writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Rate limit exceeded. Please try again later.")
			return
		}
		next(w, r)
	}
}

func (s *Server) rateLimitFailedLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		failedKey := ip + ":failed_login"

		if s.rateLimiter.isBlocked(failedKey) {
			writeError(w, http.StatusTooManyRequests, "too_many_failed_logins", "Too many failed login attempts. Please try again later.")
			return
		}

		rw := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next(rw, r)

		if rw.statusCode == http.StatusUnauthorized {
			s.rateLimiter.increment(failedKey, loginFailLimit, loginFailWindow)
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

func (sr *statusRecorder) Unwrap() http.ResponseWriter {
	return sr.ResponseWriter
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

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := s.db.PingContext(ctx); err != nil {
		slog.Error("health check db ping failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "unhealthy", "Database connection failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	count := s.requestCount.Load()
	var avgDuration float64
	if count > 0 {
		avgDuration = float64(s.requestDuration.Load()) / float64(count) / 1e6
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"requests_total":  count,
		"requests_errors": s.requestErrors.Load(),
		"avg_duration_ms": avgDuration,
	})
}

func (s *Server) signupHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON in request body")
		return
	}

	email := normalizeEmail(req.Email)
	if email == "" {
		writeError(w, http.StatusBadRequest, "email_required", "Email is required")
		return
	}

	if !isValidEmail(email) {
		writeError(w, http.StatusBadRequest, "invalid_email", "Invalid email format")
		return
	}

	if len(email) > 254 {
		writeError(w, http.StatusBadRequest, "email_too_long", "Email must be less than 254 characters")
		return
	}

	plaintextKey := uuid.New().String()
	id, err := s.db.CreateUser(r.Context(), email, plaintextKey)
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

	user, err := s.db.GetUserByID(r.Context(), id)
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

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getUserHandler(w http.ResponseWriter, r *http.Request) {
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

	user, err := s.db.GetUserByAPIKey(r.Context(), apiKey)
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

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
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

	user, err := s.db.GetUserByAPIKey(r.Context(), apiKey)
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

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) generateUUIDHandler(w http.ResponseWriter, r *http.Request) {
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

	user, err := s.db.GetUserByAPIKey(r.Context(), apiKey)
	if err != nil {
		if dbErr, ok := err.(DBError); ok && dbErr.Code == "invalid_api_key" {
			writeError(w, http.StatusUnauthorized, dbErr.Code, dbErr.Message)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to authenticate")
		return
	}

	var u string
	for i := 0; i < uuidCollisionRetries; i++ {
		newUUID, err := uuid.NewV7()
		if err != nil {
			slog.Error("failed to generate uuid", "error", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to generate UUID")
			return
		}
		u = newUUID.String()
		err = s.db.CreateUUIDRecord(r.Context(), u, user.ID)
		if err == nil {
			break
		}
		if dbErr, ok := err.(DBError); !ok || dbErr.Code != "uuid_exists" {
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to store UUID")
			return
		}
		// First collision - record it and return the fun message
		if i == 0 {
			if err := s.db.CreateCollisionRecord(r.Context(), user.ID); err != nil {
				slog.Error("failed to record collision", "error", err)
			}
			writeJSON(w, http.StatusOK, map[string]string{
				"message": "Congrats!!! You generated a duplicate UUID. The chances of that are approximately 1 in 2^122. You should buy a lottery ticket!",
				"uuid":    "",
			})
			return
		}
		slog.Warn("uuid collision, retrying", "attempt", i+1)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to generate unique UUID after retries")
		return
	}

	resp := UUIDResponse{
		UUID:      u,
		UserID:    user.ID,
		Email:     user.Email,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, resp)
}
