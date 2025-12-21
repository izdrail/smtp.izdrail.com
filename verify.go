package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

/* ============================================================
   CONFIG
============================================================ */
var (
	maxWorkers         = 4
	globalRateLimit    = 42 // max SMTP servers per minute
	capabilityCacheTTL = 30 * time.Minute
	serverAddr         = ":1240"
	dbFile             = "scans.db"
	defaultTimeout     = 30 * time.Second // Sync request timeout
)

func initConfig() {
	if port := os.Getenv("PORT"); port != "" {
		if !strings.HasPrefix(port, ":") {
			serverAddr = ":" + port
		} else {
			serverAddr = port
		}
	}
	if db := os.Getenv("DB_PATH"); db != "" {
		dbFile = db
	}
}

/* ============================================================
   PROVIDERS
============================================================ */
type Provider string

const (
	ProviderGoogle    Provider = "google"
	ProviderMicrosoft Provider = "microsoft"
	ProviderYahoo     Provider = "yahoo"
	ProviderApple     Provider = "apple"
	ProviderCustom    Provider = "custom"
)

func detectProvider(domain string) Provider {
	switch strings.ToLower(domain) {
	case "gmail.com", "googlemail.com":
		return ProviderGoogle
	case "outlook.com", "hotmail.com", "live.com", "msn.com":
		return ProviderMicrosoft
	case "yahoo.com", "yahoo.co.uk", "ymail.com":
		return ProviderYahoo
	case "icloud.com", "me.com", "mac.com":
		return ProviderApple
	default:
		return ProviderCustom
	}
}

func isOAuthOnly(p Provider) bool {
	return p != ProviderCustom
}

/* ============================================================
   SMTP AUTH
============================================================ */
type loginAuth struct {
	username, password string
}

func (a *loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) { return "LOGIN", []byte(a.username), nil }
func (a *loginAuth) Next(from []byte, more bool) ([]byte, error) {
	if more {
		if string(from) == "Password:" {
			return []byte(a.password), nil
		}
		return []byte(a.username), nil
	}
	return nil, nil
}

type plainAuth struct {
	username, password string
}

func (a *plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.username + "\x00" + a.password), nil
}
func (a *plainAuth) Next([]byte, bool) ([]byte, error) { return nil, nil }

/* ============================================================
   SMTP CAPABILITIES CACHE
============================================================ */
type SMTPCapabilities struct {
	Host        string   `json:"host"`
	AuthMethods []string `json:"auth_methods"`
	StartTLS    bool     `json:"starttls"`
}

type capEntry struct {
	caps SMTPCapabilities
	exp  time.Time
}

var (
	capMu    sync.RWMutex
	capCache = map[string]capEntry{}
)

var ErrRateLimit = errors.New("rate limit exceeded")

/* ============================================================
   GLOBAL SMTP RATE LIMIT
============================================================ */
var (
	globalRateMu sync.Mutex
	tokens       = globalRateLimit
	refillTicker *time.Ticker
)

func initRateLimiter() {
	tokens = globalRateLimit
	refillTicker = time.NewTicker(time.Minute)
	go func() {
		for range refillTicker.C {
			globalRateMu.Lock()
			tokens = globalRateLimit
			globalRateMu.Unlock()
			log.Printf("[RateLimiter] Tokens refilled to %d", globalRateLimit)
		}
	}()
}

func acquireToken() bool {
	globalRateMu.Lock()
	defer globalRateMu.Unlock()
	if tokens > 0 {
		tokens--
		return true
	}
	log.Printf("[RateLimiter] Rate limit exceeded! Tokens exhausted.")
	return false
}

/* ============================================================
   JOB MANAGEMENT
============================================================ */
type VerifyJob struct {
	ID       string
	Email    string
	Password string
	Ctx      context.Context    // For cancellation
	Cancel   context.CancelFunc // Cancel function
}

type JobResult struct {
	Status       string            `json:"status"`
	Error        string            `json:"error,omitempty"`
	Capabilities *SMTPCapabilities `json:"capabilities,omitempty"`
	Headers      []string          `json:"headers,omitempty"` // Legacy: Now subset of Logs or just empty
	Logs         []string          `json:"logs,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	CompletedAt  time.Time         `json:"completed_at"`
}

type WorkerState struct {
	ID         int       `json:"id"`
	Status     string    `json:"status"` // "idle" or "processing"
	CurrentJob string    `json:"current_job,omitempty"` // Email
	JobID      string    `json:"job_id,omitempty"`      // Job ID for cancellation
	StartedAt  time.Time `json:"started_at,omitempty"`
}

type JobManager struct {
	mu        sync.RWMutex
	queue     chan VerifyJob
	waitChans sync.Map // map[string]chan JobResult
}

var (
	jobManager        = &JobManager{
		queue: make(chan VerifyJob, 1000), // Larger buffer for bulk
	}
	db                *sql.DB
	activeLoggers     sync.Map // map[string]*SMTPLogger
	workerStates      sync.Map // map[int]WorkerState
	activeCancelFuncs sync.Map // map[string]context.CancelFunc (JobID -> CancelFunc)
)

/* ============================================================
   SMTP LOGGER
============================================================ */
type SMTPLogger struct {
	mu      sync.Mutex
	records []string
}

func (l *SMTPLogger) Log(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	l.records = append(l.records, msg)
	log.Printf("[SMTP] %s", msg) // Also log to stdout
}

func (l *SMTPLogger) Dump() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.records...)
}



/* ============================================================
   SMTP LOGIC
============================================================ */
func discoverSMTP(domain string) ([]string, error) {
	log.Printf("[Discovery] Looking up MX records for domain: %s", domain)
	var hosts []string
	
	// 1. MX Records
	mx, err := net.LookupMX(domain)
	if err != nil {
		log.Printf("[Discovery] MX lookup failed for %s: %v", domain, err)
	} else {
		for _, m := range mx {
			hosts = append(hosts, strings.TrimSuffix(m.Host, "."))
		}
	}

	// 2. Fallbacks
	// Always add common subdomains because sometimes MX records point to non-responsive gateways or filter heavily
	hosts = append(hosts, "smtp."+domain)
	hosts = append(hosts, "mail."+domain)
	// hosts = append(hosts, domain) // Sometimes the domain itself is the mail server

	if len(hosts) == 0 {
		return nil, errors.New("no SMTP hosts found")
	}
	
	log.Printf("[Discovery] Candidates for %s: %v", domain, hosts)
	return hosts, nil
}

func connectSMTP(ctx context.Context, host, port string, implicitTLS bool, logger *SMTPLogger) (*smtp.Client, error) {
	addr := net.JoinHostPort(host, port)
	logger.Log("Connecting to %s (ImplicitTLS=%v)", addr, implicitTLS)

	var c *smtp.Client
	var err error
	
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	if implicitTLS {
		// Port 465: TLS connection from start
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			logger.Log("TCP Connection to %s failed: %v", addr, err)
			return nil, err
		}
		
		tlsConfig := &tls.Config{ServerName: host, InsecureSkipVerify: true}
		tlsConn := tls.Client(conn, tlsConfig)
		// Handshake with Context support (Go 1.14+)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			logger.Log("TLS Handshake to %s failed: %v", addr, err)
			return nil, err
		}
		
		c, err = smtp.NewClient(tlsConn, host)
		if err != nil {
			logger.Log("SMTP handshake (TLS) with %s failed: %v", addr, err)
			return nil, err
		}
		return c, nil
	}
	
	// Port 25, 587, 2525: STARTTLS or Plain
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		logger.Log("Connection to %s failed: %v", addr, err)
		return nil, err
	}
	c, err = smtp.NewClient(conn, host)
	if err != nil {
		logger.Log("SMTP handshake with %s failed: %v", addr, err)
		return nil, err
	}
	// Negotiate STARTTLS if available
	if ok, _ := c.Extension("STARTTLS"); ok {
		logger.Log("STARTTLS supported on %s, negotiating...", host)
		if err := c.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true}); err != nil {
			c.Close()
			logger.Log("STARTTLS negotiation failed: %v", err)
			return nil, err
		}
		logger.Log("STARTTLS successful")
	} else {
		logger.Log("STARTTLS NOT supported on %s", host)
	}
	return c, nil
}

func probeCapabilities(c *smtp.Client, host string) SMTPCapabilities {
	capMu.RLock()
	entry, ok := capCache[host]
	capMu.RUnlock()
	if ok && time.Now().Before(entry.exp) {
		log.Printf("[Cache] Hit capability cache for %s", host)
		return entry.caps
	}
	log.Printf("[Cache] Miss capability cache for %s, probing...", host)
	caps := SMTPCapabilities{Host: host}

	if ok, ext := c.Extension("AUTH"); ok {
		caps.AuthMethods = strings.Fields(ext)
	}

	if ok, _ := c.Extension("STARTTLS"); ok {
		caps.StartTLS = true
	}

	capMu.Lock()
	capCache[host] = capEntry{caps, time.Now().Add(capabilityCacheTTL)}
	capMu.Unlock()
	return caps
}

func tryAuth(c *smtp.Client, caps SMTPCapabilities, email, password string) error {
	for _, m := range caps.AuthMethods {
		log.Printf("[Auth] Trying auth method %s for %s", m, email)
		switch strings.ToUpper(m) {
		case "LOGIN":
			return c.Auth(&loginAuth{email, password})
		case "PLAIN":
			return c.Auth(&plainAuth{email, password})
		}
	}
	log.Printf("[Auth] No supported auth methods found in %v", caps.AuthMethods)
	return errors.New("no supported auth methods")
}

func verifySMTP(ctx context.Context, jobID, email, password string) (*SMTPCapabilities, []string, error) {
	// Create or Reuse Logger
	logger := &SMTPLogger{}
	if jobID != "" {
		activeLoggers.Store(jobID, logger)
		defer activeLoggers.Delete(jobID)
	}

	if !acquireToken() {
		logger.Log("Global rate limit exceeded (42/min)")
		return nil, logger.Dump(), ErrRateLimit
	}
	
	// Check Context
	select {
	case <-ctx.Done():
		logger.Log("Verification cancelled by user.")
		return nil, logger.Dump(), ctx.Err()
	default:
	}

	log.Printf("[Verify] Starting verification for %s", email)
	logger.Log("Starting verification for %s", email)
	
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, logger.Dump(), errors.New("invalid email format")
	}
	if isOAuthOnly(detectProvider(parts[1])) {
		logger.Log("Provider %s requires OAuth, skipping password auth", parts[1])
		return nil, logger.Dump(), errors.New("provider requires OAuth")
	}

	hosts, err := discoverSMTP(parts[1])
	if err != nil {
		logger.Log("Discovery failed: %v", err)
		return nil, logger.Dump(), err
	}

	// Define ports to try
	ports := []struct{
		Port        string
		ImplicitTLS bool
	}{
		{"465", true},   // Legacy SMTPS (often most reliable for auth)
		{"587", false},  // Submission (STARTTLS)
		{"25", false},   // Relay (STARTTLS)
		{"2525", false}, // Alternative
	}

	var lastErr error
	for _, host := range hosts {
		for _, p := range ports {
			// Check Context
			select {
			case <-ctx.Done():
				logger.Log("Verification cancelled.")
				return nil, logger.Dump(), ctx.Err()
			default:
			}
			
			logger.Log("Trying host: %s Port: %s", host, p.Port)
			c, err := connectSMTP(ctx, host, p.Port, p.ImplicitTLS, logger)
			if err != nil {
				lastErr = err
				continue
			}
			
			caps := probeCapabilities(c, host)
			logger.Log("Capabilities: Auth=%v TLS=%v", caps.AuthMethods, caps.StartTLS)
			
			if err := tryAuth(c, caps, email, password); err != nil {
				logger.Log("Auth failed: %v", err)
				c.Close()
				lastErr = err
				continue 
			}

			logger.Log("Authentication successful on %s:%s!", host, p.Port)
			c.Quit()
			return &caps, logger.Dump(), nil
		}
	}
	
	logger.Log("Verification failed on all hosts/ports. Last error: %v", lastErr)
	return nil, logger.Dump(), lastErr
}

/* ============================================================
   DATABASE
============================================================ */
func initDB() error {
	var err error
	dsn := fmt.Sprintf("%s?_parseTime=true&_journal_mode=WAL", dbFile)
	log.Printf("[DB] Opening database at %s", dbFile)
	db, err = sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}
	if err := db.Ping(); err != nil {
		return err
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		email TEXT,
		domain TEXT,
		status TEXT,
		password TEXT,
		error TEXT,
		auth_method TEXT,
		headers TEXT,
		logs TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME
	)`)
	
	if err == nil {
		log.Println("[DB] Running Ensure-Schema migrations...")
		db.Exec(`ALTER TABLE scans ADD COLUMN created_at DATETIME`)
		db.Exec(`UPDATE scans SET created_at = completed_at WHERE created_at IS NULL`)
		db.Exec(`ALTER TABLE scans ADD COLUMN completed_at DATETIME`)
		db.Exec(`ALTER TABLE scans ADD COLUMN error TEXT`)
		// New columns
		db.Exec(`ALTER TABLE scans ADD COLUMN password TEXT`)
		db.Exec(`ALTER TABLE scans ADD COLUMN logs TEXT`)
	}
	return err
}

func createPendingScan(id, email, password string) error {
	domain := ""
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		domain = parts[1]
	}
	log.Printf("[DB] Inserting PENDING scan: %s (%s)", id, email)
	// We save password here for retry logic
	_, err := db.Exec(`INSERT INTO scans(id, email, domain, status, password, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		id, email, domain, "pending", password, time.Now())
	return err
}

func updateScanResult(id string, res JobResult) error {
	hdrJSON, _ := json.Marshal(res.Headers) // Legacy Headers (which were logs)
	logsJSON, _ := json.Marshal(res.Logs)
	
	log.Printf("[DB] Updating scan result for %s: %s (Err: %v)", id, res.Status, res.Error)
	
	// auth_method logic: get from caps if avail, or empty
	authMethod := ""
	if res.Capabilities != nil && len(res.Capabilities.AuthMethods) > 0 {
		authMethod = strings.Join(res.Capabilities.AuthMethods, ",")
	}
	
	_, err := db.Exec(`UPDATE scans SET status=?, error=?, headers=?, logs=?, auth_method=?, completed_at=? WHERE id=?`,
		res.Status, res.Error, string(hdrJSON), string(logsJSON), authMethod, res.CompletedAt, id)
	return err
}

/* ============================================================
   WORKER POOL
============================================================ */
func startWorkers(n int) {
	log.Printf("[Worker] Starting %d workers", n)
	for i := 0; i < n; i++ {
		go worker(i)
	}
}

func worker(id int) {
	log.Printf("[Worker %d] Started", id)
	workerStates.Store(id, WorkerState{ID: id, Status: "idle", StartedAt: time.Now()})

	for job := range jobManager.queue {
		log.Printf("[Worker %d] Processing job %s (%s)", id, job.ID, job.Email)
		
		// Update Worker State
		workerStates.Store(id, WorkerState{
			ID:         id,
			Status:     "processing",
			CurrentJob: job.Email,
			JobID:      job.ID,
			StartedAt:  time.Now(),
		})

		// Setup Context (if not already set, though it should be)
		if job.Ctx == nil {
			job.Ctx, job.Cancel = context.WithCancel(context.Background())
		}
		activeCancelFuncs.Store(job.ID, job.Cancel)

		var caps *SMTPCapabilities
		var logs []string
		var err error

		// Retry Loop for Rate Limiting
		for {
			// Check Context
			select {
			case <-job.Ctx.Done():
				err = job.Ctx.Err()
				break
			default:
			}

			caps, logs, err = verifySMTP(job.Ctx, job.ID, job.Email, job.Password)
			if err == ErrRateLimit {
				log.Printf("[Worker %d] Rate limit hit for %s, sleeping 5s...", id, job.ID)
				
				// Sleep with context awareness
				select {
				case <-time.After(5 * time.Second):
					continue
				case <-job.Ctx.Done():
					err = job.Ctx.Err()
					break
				}
			}
			break
		}

		res := JobResult{
			Status:       "success",
			Capabilities: caps,
			Headers:      logs, // Keep for legacy/summary
			Logs:         logs, // Full logs
			CreatedAt:    time.Now(),
			CompletedAt:  time.Now(),
		}
		if err != nil {
			if errors.Is(err, context.Canceled) {
				res.Status = "cancelled"
				res.Error = "cancelled by user"
			} else {
				res.Status = "failed"
				res.Error = err.Error()
			}
		}

		// Update Database
		if dbErr := updateScanResult(job.ID, res); dbErr != nil {
			log.Printf("[Worker %d] Failed to update DB for job %s: %v", id, job.ID, dbErr)
		}

		// Notify Synchronous Waiters
		if ch, ok := jobManager.waitChans.Load(job.ID); ok {
			// Cast interface{} back to chan
			if resultChan, ok := ch.(chan JobResult); ok {
				resultChan <- res
				close(resultChan)
			}
			jobManager.waitChans.Delete(job.ID)
		}
		
		// Cleanup
		activeCancelFuncs.Delete(job.ID)
		if job.Cancel != nil {
			job.Cancel()
		}
		workerStates.Store(id, WorkerState{ID: id, Status: "idle"})
	}
}

/* ============================================================
   HTTP HANDLERS
============================================================ */
type VerifyRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// verifyHandler handles synchronous verification by waiting for the background job
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	
	// Parse Delimiters in Email field if user pasted "email:pass"
	if req.Password == "" {
		if strings.Contains(req.Email, "|") {
			parts := strings.SplitN(req.Email, "|", 2)
			req.Email = strings.TrimSpace(parts[0])
			req.Password = strings.TrimSpace(parts[1])
		} else if strings.Contains(req.Email, ":") {
			parts := strings.SplitN(req.Email, ":", 2)
			req.Email = strings.TrimSpace(parts[0])
			req.Password = strings.TrimSpace(parts[1])
		}
	}
	
	id := uuid.NewString()
	log.Printf("[API] Sync Request received: %s (%s)", id, req.Email)

	// 1. Insert Pending into DB
	if err := createPendingScan(id, req.Email, req.Password); err != nil {
		log.Printf("[API] Failed to insert pending scan: %v", err)
		http.Error(w, "db error", 500)
		return
	}

	// 2. Register Wait Channel
	resultChan := make(chan JobResult, 1)
	jobManager.waitChans.Store(id, resultChan)

	// 3. Push to Queue
	select {
	case jobManager.queue <- VerifyJob{ID: id, Email: req.Email, Password: req.Password}:
		log.Printf("[API] Job %s queued", id)
	default:
		log.Printf("[API] Queue full, rejecting job %s", id)
		jobManager.waitChans.Delete(id)
		updateScanResult(id, JobResult{Status: "failed", Error: "queue full", CompletedAt: time.Now()})
		http.Error(w, "queue full", 503)
		return
	}

	// 4. Wait for Result or Timeout
	select {
	case res := <-resultChan:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	case <-time.After(defaultTimeout):
		log.Printf("[API] Timeout waiting for job %s", id)
		// Clean up, but job might still be in queue/processing
		jobManager.waitChans.Delete(id)
		// We don't cancel the job essentially, just the client request
		http.Error(w, "timeout", 504)
	}
}

func verifyAsyncHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	
	// Parse Delimiters in Email field if user pasted "email:pass"
	if req.Password == "" {
		if strings.Contains(req.Email, "|") {
			parts := strings.SplitN(req.Email, "|", 2)
			req.Email = strings.TrimSpace(parts[0])
			req.Password = strings.TrimSpace(parts[1])
		} else if strings.Contains(req.Email, ":") {
			parts := strings.SplitN(req.Email, ":", 2)
			req.Email = strings.TrimSpace(parts[0])
			req.Password = strings.TrimSpace(parts[1])
		}
	}

	id := uuid.NewString()
	log.Printf("[API] Async Request received: %s (%s)", id, req.Email)

	if err := createPendingScan(id, req.Email, req.Password); err != nil {
		log.Printf("[API] Failed to insert pending scan: %v", err)
		http.Error(w, "db error", 500)
		return
	}

	select {
	case jobManager.queue <- VerifyJob{ID: id, Email: req.Email, Password: req.Password}:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"job_id": id, "status": "pending"})
	default:
		updateScanResult(id, JobResult{Status: "failed", Error: "queue full", CompletedAt: time.Now()})
		http.Error(w, "queue full", 503)
	}
}

func verifyFileHandler(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", 400)
		return
	}
	defer file.Close()
	
	log.Printf("[API] File Upload received")
	sc := bufio.NewScanner(file)
	var jobIDs []string

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		
		var p []string
		if strings.Contains(line, "|") {
			p = strings.SplitN(line, "|", 2)
		} else {
			p = strings.SplitN(line, ":", 2)
		}
		
		if len(p) != 2 {
			continue
		}
		id := uuid.NewString()
		email := strings.TrimSpace(p[0])
		password := strings.TrimSpace(p[1])

		if err := createPendingScan(id, email, password); err != nil {
			log.Printf("[API] Failed to insert pending scan for %s: %v", email, err)
			continue
		}

		select {
		case jobManager.queue <- VerifyJob{ID: id, Email: email, Password: password}:
			jobIDs = append(jobIDs, id)
		default:
			log.Printf("[API] Queue full during file upload for %s", email)
		}
	}
	
	log.Printf("[API] File Upload processed, queued %d jobs", len(jobIDs))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "queued", "job_ids": jobIDs, "count": len(jobIDs)})
}

func jobStatusHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	// Check Active Loggers first (Realtime)
	if val, ok := activeLoggers.Load(id); ok {
		logger := val.(*SMTPLogger)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     id,
			"status": "processing",
			"logs":   logger.Dump(),
		})
		return
	}

	// Fallback to DB
	var status, logsJSON string
	err := db.QueryRow("SELECT status, COALESCE(logs,'[]') FROM scans WHERE id = ?", id).Scan(&status, &logsJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"job not found"}`, 404)
		} else {
			http.Error(w, "db error", 500)
		}
		return
	}
	
	var logs []string
	json.Unmarshal([]byte(logsJSON), &logs)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     id,
		"status": status,
		"logs":   logs,
	})
}

/* ============================================================
   WORKER APIs
============================================================ */
func stopAllJobs() {
	log.Println("[Worker] Stopping ALL jobs...")
	activeCancelFuncs.Range(func(key, value interface{}) bool {
		cancel := value.(context.CancelFunc)
		cancel()
		activeCancelFuncs.Delete(key)
		return true
	})
}

func getWorkersHandler(w http.ResponseWriter, r *http.Request) {
	var states []WorkerState
	workerStates.Range(func(key, value interface{}) bool {
		states = append(states, value.(WorkerState))
		return true
	})
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(states)
}

func stopWorkersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	
	type StopReq struct {
		All bool `json:"all"`
		ID  int  `json:"id"` // Worker ID (optional, to stop current job of specific worker)
	}
	var req StopReq
	json.NewDecoder(r.Body).Decode(&req)

	if req.All {
		stopAllJobs()
		w.Write([]byte(`{"status":"all_stopped"}`))
		return
	}
	
	// Stop specific worker's job
	if val, ok := workerStates.Load(req.ID); ok {
		state := val.(WorkerState)
		if state.Status == "processing" && state.JobID != "" {
			if cancelVal, ok := activeCancelFuncs.Load(state.JobID); ok {
				cancel := cancelVal.(context.CancelFunc)
				cancel()
				log.Printf("[Worker API] Stopped Worker %d (Job %s)", req.ID, state.JobID)
				w.Write([]byte(`{"status":"stopped"}`))
				return
			}
		}
	}
	
	http.Error(w, "worker not active or job not found", 404)
}

/* ============================================================
   API DOCS & HISTORY
============================================================ */
type Scan struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	Domain     string    `json:"domain"`
	Status     string    `json:"status"`
	Password   string    `json:"password,omitempty"` // Add Password
	Error      string    `json:"error,omitempty"`
	Headers    string    `json:"headers,omitempty"`
	Logs       string    `json:"logs,omitempty"`     // Add Logs
	AuthMethod string    `json:"auth_method,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type PaginationMeta struct {
	Total int `json:"total"`
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

type ScansResponse struct {
	Data       []Scan          `json:"data"`
	Pagination PaginationMeta  `json:"pagination"`
}

func getScansHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] Get History")
	
	// Parse Query Params
	email := r.URL.Query().Get("email")
	status := r.URL.Query().Get("status")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	page := 1
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}
	limit := 50
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000000 {
		limit = l
	}
	offset := (page - 1) * limit

	// Base Query
	whereClause := "WHERE 1=1"
	var args []interface{}

	if email != "" {
		whereClause += " AND email LIKE ?"
		args = append(args, "%"+email+"%")
	}
	if status != "" {
		whereClause += " AND status = ?"
		args = append(args, status)
	}

	// Count Total
	var total int
	countQuery := "SELECT COUNT(*) FROM scans " + whereClause
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		log.Printf("[DB] Count error: %v", err)
		http.Error(w, "db error", 500)
		return
	}

	// Fetch Data
	query := fmt.Sprintf(`
		SELECT id, email, domain, status, COALESCE(password, ''), COALESCE(error, ''), COALESCE(headers,'[]'), COALESCE(logs,'[]'), COALESCE(auth_method,''), created_at, completed_at 
		FROM scans 
		%s 
		ORDER BY created_at DESC 
		LIMIT ? OFFSET ?`, whereClause)
	
	args = append(args, limit, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("[DB] Query error: %v", err)
		http.Error(w, "db error", 500)
		return
	}
	defer rows.Close()

	scans := make([]Scan, 0)
	for rows.Next() {
		var scan Scan
		var headersJSON string
		var logsJSON string
		var completedAt sql.NullTime
		
		if err := rows.Scan(&scan.ID, &scan.Email, &scan.Domain, &scan.Status, &scan.Password, &scan.Error, &headersJSON, &logsJSON, &scan.AuthMethod, &scan.CreatedAt, &completedAt); err != nil {
			log.Printf("[DB] Scan error: %v", err)
			continue
		}
		if completedAt.Valid {
			scan.CompletedAt = completedAt.Time
		}
		
		scan.Headers = headersJSON
		scan.Logs = logsJSON
		
		scans = append(scans, scan)
	}

	resp := ScansResponse{
		Data: scans,
		Pagination: PaginationMeta{
			Total: total,
			Page:  page,
			Limit: limit,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func deleteScansHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API] Clearing History")
	stopAllJobs() // Stop all active jobs first
	_, err := db.Exec(`DELETE FROM scans`)
	if err != nil {
		http.Error(w, "delete failed", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func docsHandler(w http.ResponseWriter, r *http.Request) {
	apiDocs := []map[string]string{
		{"path": "/verify", "method": "POST", "desc": "Sync verify"},
		{"path": "/verify/async", "method": "POST", "desc": "Async verify"},
		{"path": "/verify/file", "method": "POST", "desc": "Bulk file verify"},
		{"path": "/verify/status", "method": "GET", "desc": "Check job status"},
		{"path": "/api/scans", "method": "GET", "desc": "Get history"},
		{"path": "/api/export", "method": "GET", "desc": "Export scans"},
		{"path": "/api/send-test", "method": "POST", "desc": "Send test email"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(apiDocs)
}

func exportScansHandler(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format") // csv, txt
	status := r.URL.Query().Get("status") // all, success, failed
	
	whereClause := "WHERE 1=1"
	var args []interface{}
	
	if status != "" {
		whereClause += " AND status = ?"
		args = append(args, status)
	}
	
	query := fmt.Sprintf("SELECT email, password, domain, status FROM scans %s ORDER BY created_at DESC", whereClause)
	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	defer rows.Close()
	
	if format == "txt" {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", "attachment; filename=verified_emails.txt")
		for rows.Next() {
			var email, password, domain, status string
			rows.Scan(&email, &password, &domain, &status)
			fmt.Fprintf(w, "%s:%s\n", email, password)
		}
		return
	}
	
	// Default to CSV
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=verified_emails.csv")
	fmt.Fprintln(w, "Email,Password,Domain,Status")
	for rows.Next() {
		var email, password, domain, status string
		rows.Scan(&email, &password, &domain, &status)
		fmt.Fprintf(w, "%s,%s,%s,%s\n", email, password, domain, status)
	}
}

func sendTestEmailHandler(w http.ResponseWriter, r *http.Request) {
	type SendTestReq struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		To       string `json:"to"`
		Subject  string `json:"subject"`
		Body     string `json:"body"`
	}
	var req SendTestReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	
	if req.Email == "" || req.Password == "" || req.To == "" {
		http.Error(w, "missing required fields", 400)
		return
	}
	
	parts := strings.Split(req.Email, "@")
	if len(parts) != 2 {
		http.Error(w, "invalid email", 400)
		return
	}
	
	hosts, err := discoverSMTP(parts[1])
	if err != nil {
		http.Error(w, "discovery failed", 500)
		return
	}
	
	ports := []struct{
		Port        string
		ImplicitTLS bool
	}{
		{"465", true},
		{"587", false},
		{"25", false},
	}
	
	var lastErr error
	sent := false
	
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	
	logger := &SMTPLogger{}

	for _, host := range hosts {
		for _, p := range ports {
			c, err := connectSMTP(ctx, host, p.Port, p.ImplicitTLS, logger)
			if err != nil {
				lastErr = err
				continue
			}
			
			caps := probeCapabilities(c, host)
			if err := tryAuth(c, caps, req.Email, req.Password); err != nil {
				c.Close()
				lastErr = err
				continue
			}
			
			// Auth worked, now send
			if err := c.Mail(req.Email); err != nil {
				c.Close()
				lastErr = err
				continue
			}
			if err := c.Rcpt(req.To); err != nil {
				c.Close()
				lastErr = err
				continue
			}
			
			wc, err := c.Data()
			if err != nil {
				c.Close()
				lastErr = err
				continue
			}
			
			msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", req.Email, req.To, req.Subject, req.Body)
			_, err = wc.Write([]byte(msg))
			if err != nil {
				wc.Close()
				c.Close()
				lastErr = err
				continue
			}
			err = wc.Close()
			if err != nil {
				c.Close()
				lastErr = err
				continue
			}
			
			c.Quit()
			sent = true
			break
		}
		if sent { break }
	}
	
	if sent {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "sent"})
	} else {
		http.Error(w, fmt.Sprintf("failed to send: %v", lastErr), 500)
	}
}

/* ============================================================
   MAIN
============================================================ */
func main() {
	// Setup standard logger to print microseconds for better debugging
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	initConfig()

	if err := initDB(); err != nil {
		log.Fatalf("Failed to init DB: %v", err)
	}

	initRateLimiter()
	startWorkers(maxWorkers)

	r := mux.NewRouter()
	r.Handle("/verify", http.HandlerFunc(verifyHandler)).Methods("POST")
	r.Handle("/verify/file", http.HandlerFunc(verifyFileHandler)).Methods("POST")
	r.Handle("/verify/async", http.HandlerFunc(verifyAsyncHandler)).Methods("POST")
	r.Handle("/verify/status", http.HandlerFunc(jobStatusHandler)).Methods("GET")
	r.Handle("/docs", http.HandlerFunc(docsHandler)).Methods("GET")
	r.Handle("/api/scans", http.HandlerFunc(getScansHandler)).Methods("GET")
	r.Handle("/api/scans", http.HandlerFunc(deleteScansHandler)).Methods("DELETE")
	r.Handle("/api/export", http.HandlerFunc(exportScansHandler)).Methods("GET")
	r.Handle("/api/send-test", http.HandlerFunc(sendTestEmailHandler)).Methods("POST")
	r.Handle("/api/workers", http.HandlerFunc(getWorkersHandler)).Methods("GET")
	r.Handle("/api/workers/stop", http.HandlerFunc(stopWorkersHandler)).Methods("POST")
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	}).Methods("GET")
	
	srv := &http.Server{Addr: serverAddr, Handler: r}

	go func() {
		log.Printf("Server running on %s", serverAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Listen error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced shutdown: %v", err)
	}
	log.Println("Server exited")
}