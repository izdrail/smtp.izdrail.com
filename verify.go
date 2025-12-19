package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
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
const (
	maxWorkers         = 4
	globalRateLimit    = 42 // max SMTP servers per minute
	capabilityCacheTTL = 30 * time.Minute
	serverAddr         = ":8080"
	dbFile             = "scans.db"
)

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
	return false
}

/* ============================================================
   JOB MANAGEMENT
============================================================ */
type VerifyJob struct {
	ID       string
	Email    string
	Password string
}

type JobResult struct {
	Status       string            `json:"status"`
	Error        string            `json:"error,omitempty"`
	Capabilities *SMTPCapabilities `json:"capabilities,omitempty"`
	Headers      []string          `json:"headers,omitempty"`
	CreatedAt    time.Time         `json:"created_at,omitempty"`
	CompletedAt  time.Time         `json:"completed_at,omitempty"`
}

type JobManager struct {
	mu      sync.RWMutex
	results map[string]JobResult
	queue   chan VerifyJob
}

var jobManager = &JobManager{
	results: make(map[string]JobResult),
	queue:   make(chan VerifyJob, 100),
}

var db *sql.DB

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
	l.records = append(l.records, fmt.Sprintf(format, args...))
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
	mx, err := net.LookupMX(domain)
	if err != nil || len(mx) == 0 {
		return nil, errors.New("no MX records found")
	}
	var hosts []string
	for _, m := range mx {
		hosts = append(hosts, strings.TrimSuffix(m.Host, "."))
	}
	return hosts, nil
}

func connectSMTP(host string, logger *SMTPLogger) (*smtp.Client, error) {
	logger.Log("Connecting to %s:587", host)
	conn, err := net.DialTimeout("tcp", host+":587", 5*time.Second)
	if err != nil {
		logger.Log("Connection failed: %v", err)
		return nil, err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		logger.Log("SMTP handshake failed: %v", err)
		return nil, err
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		logger.Log("Starting TLS")
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			c.Close()
			logger.Log("STARTTLS failed: %v", err)
			return nil, err
		}
	}
	return c, nil
}

func probeCapabilities(c *smtp.Client, host string) SMTPCapabilities {
	capMu.RLock()
	entry, ok := capCache[host]
	capMu.RUnlock()
	if ok && time.Now().Before(entry.exp) {
		return entry.caps
	}
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
		switch strings.ToUpper(m) {
		case "LOGIN":
			return c.Auth(&loginAuth{email, password})
		case "PLAIN":
			return c.Auth(&plainAuth{email, password})
		}
	}
	return errors.New("no supported auth methods")
}

func verifySMTP(email, password string) (*SMTPCapabilities, []string, error) {
	reqLogger := &SMTPLogger{}
	if !acquireToken() {
		reqLogger.Log("Rate limit exceeded")
		return nil, reqLogger.Dump(), errors.New("global SMTP rate limit exceeded (max 42 per minute)")
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, reqLogger.Dump(), errors.New("invalid email")
	}
	if isOAuthOnly(detectProvider(parts[1])) {
		return nil, reqLogger.Dump(), errors.New("provider requires OAuth")
	}
	hosts, err := discoverSMTP(parts[1])
	if err != nil {
		return nil, reqLogger.Dump(), err
	}
	for _, host := range hosts {
		c, err := connectSMTP(host, reqLogger)
		if err != nil {
			continue
		}
		caps := probeCapabilities(c, host)
		err = tryAuth(c, caps, email, password)
		c.Quit()
		if err == nil {
			return &caps, reqLogger.Dump(), nil
		}
	}
	return nil, reqLogger.Dump(), errors.New("authentication failed")
}

/* ============================================================
   DATABASE
============================================================ */
func initDB() error {
	var err error
	// Enable time parsing and WAL mode for better concurrency and reliability
	dsn := fmt.Sprintf("%s?_parseTime=true&_journal_mode=WAL", dbFile)
	db, err = sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}
	// Initial connection verification
	if err := db.Ping(); err != nil {
		return err
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		email TEXT,
		domain TEXT,
		status TEXT,
		error TEXT,
		auth_method TEXT,
		headers TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME
	)`)
	
	// Auto-migration for existing databases
	if err == nil {
		fmt.Println("Running DB migrations...")
		// SQLite might fail adding column with default CURRENT_TIMESTAMP via ALTER TABLE
		// So we add it without default, then backfill
		if _, errMig := db.Exec(`ALTER TABLE scans ADD COLUMN created_at DATETIME`); errMig != nil {
			fmt.Printf("Migration created_at: %v\n", errMig)
		} else {
			fmt.Println("Migration created_at: success")
			// Backfill existing rows
			db.Exec(`UPDATE scans SET created_at = completed_at WHERE created_at IS NULL`)
		}
		
		if _, errMig := db.Exec(`ALTER TABLE scans ADD COLUMN completed_at DATETIME`); errMig != nil {
			// Ignore duplicate column error usually
			if !strings.Contains(errMig.Error(), "duplicate") {
				fmt.Printf("Migration completed_at: %v\n", errMig)
			}
		}

		if _, errMig := db.Exec(`ALTER TABLE scans ADD COLUMN error TEXT`); errMig != nil {
			if !strings.Contains(errMig.Error(), "duplicate") {
				fmt.Printf("Migration error column: %v\n", errMig)
			}
		}
	} else {
		fmt.Printf("InitDB Create Table Error: %v\n", err)
	}
	
	return err
}

func saveScan(id, email, status, errorMsg string, headers []string) {
	domain := ""
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		domain = parts[1]
	}
	hdrJSON, _ := json.Marshal(headers)
	db.Exec(`INSERT INTO scans(id,email,domain,status,error,auth_method,headers,created_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		id, email, domain, status, errorMsg, "", string(hdrJSON), time.Now(), time.Now())
}

/* ============================================================
   WORKER POOL
============================================================ */
func startWorkers(n int) {
	for i := 0; i < n; i++ {
		go worker()
	}
}

func worker() {
	for job := range jobManager.queue {
		caps, headers, err := verifySMTP(job.Email, job.Password)
		res := JobResult{
			Status:       "success",
			Capabilities: caps,
			Headers:      headers,
			CreatedAt:    time.Now().Add(-time.Second), // Approximate
			CompletedAt:  time.Now(),
		}
		if err != nil {
			res.Status = "failed"
			res.Error = err.Error()
		}
		saveScan(job.ID, job.Email, res.Status, res.Error, headers)
		
		jobManager.mu.Lock()
		jobManager.results[job.ID] = res
		jobManager.mu.Unlock()
	}
}

/* ============================================================
   HTTP HANDLERS
============================================================ */
type VerifyRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	json.NewDecoder(r.Body).Decode(&req)
	id := uuid.NewString()
	caps, headers, err := verifySMTP(req.Email, req.Password)
	res := JobResult{
		Status:       "success",
		Capabilities: caps,
		Headers:      headers,
		CreatedAt:    time.Now(),
		CompletedAt:  time.Now(),
	}
	if err != nil {
		res.Status = "failed"
		res.Error = err.Error()
	}
	saveScan(id, req.Email, res.Status, res.Error, headers)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func verifyFileHandler(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", 400)
		return
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	var results []JobResult
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) != 2 {
			continue
		}
		id := uuid.NewString()
		caps, headers, err := verifySMTP(p[0], p[1])
		res := JobResult{
			Status:       "success",
			Capabilities: caps,
			Headers:      headers,
			CreatedAt:    time.Now(),
			CompletedAt:  time.Now(),
		}
		if err != nil {
			res.Status = "failed"
			res.Error = err.Error()
		}
		saveScan(id, p[0], res.Status, res.Error, headers)
		results = append(results, res)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func verifyAsyncHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	json.NewDecoder(r.Body).Decode(&req)
	id := uuid.NewString()
	
	// Store job as pending
	jobManager.mu.Lock()
	jobManager.results[id] = JobResult{
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	jobManager.mu.Unlock()
	
	// Send to background queue
	select {
	case jobManager.queue <- VerifyJob{id, req.Email, req.Password}:
	default:
		jobManager.mu.Lock()
		jobManager.results[id] = JobResult{
			Status: "failed",
			Error:  "job queue full",
		}
		jobManager.mu.Unlock()
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"job_id": id})
}

func jobStatusHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	jobManager.mu.RLock()
	res, ok := jobManager.results[id]
	jobManager.mu.RUnlock()
	
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"job not found"}`, http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

/* ============================================================
   API DOCS
============================================================ */
type APIEndpoint struct {
	Path        string   `json:"path"`
	Method      string   `json:"method"`
	Description string   `json:"description"`
	Params      []string `json:"params,omitempty"`
	Body        string   `json:"body,omitempty"`
}

var apiDocs = []APIEndpoint{
	{Path: "/verify", Method: "POST", Description: "Verify a single email/password synchronously", Body: `{"email":"user@example.com","password":"secret"}`},
	{Path: "/verify/file", Method: "POST", Description: "Upload a file with email:password lines for bulk verification", Body: "multipart/form-data file upload"},
	{Path: "/verify/async", Method: "POST", Description: "Submit async verification job", Body: `{"email":"user@example.com","password":"secret"}`},
	{Path: "/verify/status", Method: "GET", Description: "Check async job status", Params: []string{"id=job_id"}},
}

func docsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(apiDocs)
}

/* ============================================================
   SCAN HISTORY
============================================================ */
type Scan struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Domain    string    `json:"domain"`
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func getScansHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Handling /api/scans request") // Simple access logging

	email := r.URL.Query().Get("email")
	var query string
	var args []interface{}

	// Use COALESCE to handle potentially NULL columns to avoid Scan errors
	query = `SELECT id, email, domain, status, COALESCE(error, ''), created_at FROM scans ORDER BY created_at DESC LIMIT 100`
	if email != "" {
		query = `SELECT id, email, domain, status, COALESCE(error, ''), created_at FROM scans WHERE email LIKE ? ORDER BY created_at DESC LIMIT 100`
		args = []interface{}{"%" + email + "%"}
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		fmt.Printf("Database query error: %v\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "database query failed"})
		return
	}
	defer rows.Close()

	scans := make([]Scan, 0)
	for rows.Next() {
		var scan Scan
		// We can scan directly now since we handled NULLs in SQL and types in DSN
		if err := rows.Scan(&scan.ID, &scan.Email, &scan.Domain, &scan.Status, &scan.Error, &scan.CreatedAt); err != nil {
			fmt.Printf("Row scan error: %v\n", err)
			continue
		}
		scans = append(scans, scan)
	}
	
	if err := rows.Err(); err != nil {
		fmt.Printf("Rows iteration error: %v\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "error reading results"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func deleteScansHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec(`DELETE FROM scans`)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"delete failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

/* ============================================================
   MAIN
============================================================ */
func main() {
	if err := initDB(); err != nil {
		panic(err)
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
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	}).Methods("GET")
	
	srv := &http.Server{Addr: serverAddr, Handler: r}

	go func() {
		fmt.Println("Server running on", serverAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("Shutting down server...")
	close(jobManager.queue)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		fmt.Println("Server forced to shutdown:", err)
	}
	fmt.Println("Server exited")
}