# SMTP Email Verifier

A Go-based API service for verifying email credentials through SMTP authentication. The service supports both synchronous and asynchronous verification, with built-in rate limiting, caching, and persistent scan history.

## Features

- **Email Verification**: Verify email credentials via SMTP protocol
- **Provider Detection**: Automatic detection of major email providers (Google, Microsoft, Yahoo, Apple)
- **OAuth Awareness**: Detects providers that require OAuth and prevents unnecessary attempts
- **Async Support**: Submit bulk verification jobs and check status later
- **File Uploads**: Batch verify credentials from email:password formatted files
- **SMTP Capabilities**: Retrieves and caches SMTP server capabilities (auth methods, STARTTLS support)
- **Rate Limiting**: Global rate limiter (42 servers per minute) to prevent abuse
- **Caching**: 30-minute TTL cache for SMTP server capabilities
- **Database**: SQLite-based persistent storage of scan results
- **Worker Pool**: Configurable worker pool for handling concurrent jobs

## Getting Started

### Prerequisites

- Go 1.16 or higher
- SQLite3

### Installation

```bash
# Clone or download the project
cd smtp-verifier

# Install dependencies
go mod download

# Build the binary
go build -o smtp-verifier .
```

### Running the Server

```bash
./smtp-verifier
```

The server starts on `http://localhost:8080` by default.

## API Endpoints

### 1. Verify Single Email (Synchronous)

**Endpoint**: `POST /verify`

Verify a single email/password combination immediately.

**Request**:
```json
{
  "email": "user@example.com",
  "password": "your-password"
}
```

**Response**:
```json
{
  "status": "success",
  "capabilities": {
    "host": "smtp.google.com",
    "auth_methods": ["LOGIN", "PLAIN"],
    "starttls": true
  },
  "headers": ["Connecting to smtp.google.com:587", "Starting TLS"],
  "created_at": "2025-01-15T10:30:00Z",
  "completed_at": "2025-01-15T10:30:02Z"
}
```

### 2. Bulk File Verification

**Endpoint**: `POST /verify/file`

Upload a file with multiple email:password entries for batch verification.

**Request**: Multipart form with file containing:
```
user1@example.com:password1
user2@example.com:password2
user3@example.com:password3
```

**Response**: Array of verification results

### 3. Async Verification (Background Job)

**Endpoint**: `POST /verify/async`

Submit an email verification job to run in the background.

**Request**:
```json
{
  "email": "user@example.com",
  "password": "your-password"
}
```

**Response**:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 4. Check Job Status

**Endpoint**: `GET /verify/status?id=<job_id>`

Check the status of an async verification job.

**Response**:
```json
{
  "status": "success",
  "capabilities": {...},
  "headers": [...],
  "created_at": "2025-01-15T10:30:00Z",
  "completed_at": "2025-01-15T10:30:02Z"
}
```

### 5. Get Scan History

**Endpoint**: `GET /api/scans`

Retrieve scan history with optional email filtering.

**Query Parameters**:
- `email` (optional): Filter by email address

**Response**:
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "domain": "example.com",
    "status": "success",
    "created_at": "2025-01-15T10:30:00Z"
  }
]
```

### 6. Clear Scan History

**Endpoint**: `DELETE /api/scans`

Delete all scan records from the database.

### 7. API Documentation

**Endpoint**: `GET /docs`

Returns a JSON list of all available endpoints with descriptions.

## Configuration

Edit the constants in the code to customize behavior:

```go
const (
  maxWorkers         = 4                    // Concurrent verification workers
  globalRateLimit    = 42                   // Max SMTP servers per minute
  capabilityCacheTTL = 30 * time.Minute     // Cache expiration
  serverAddr         = ":1240"              // Server address
  dbFile             = "scans.db"           // SQLite database file
)
```

## How It Works

1. **Email Parsing**: Extracts domain from email address
2. **Provider Detection**: Identifies email provider (Gmail, Outlook, etc.)
3. **MX Lookup**: Discovers SMTP servers via DNS MX records
4. **Connection**: Connects to SMTP server on port 587 with STARTTLS
5. **Authentication**: Attempts LOGIN or PLAIN auth methods
6. **Capability Probing**: Retrieves and caches server capabilities
7. **Result Storage**: Saves results to SQLite database

## Error Handling

The service returns clear error messages for:
- Invalid email format
- OAuth-only providers (Gmail, Outlook, etc.)
- No MX records found
- SMTP connection failures
- Authentication failures
- Rate limit exceeded

## Database Schema

The SQLite database stores scans with:
- `id`: Unique job identifier
- `email`: Verified email address
- `domain`: Email domain
- `status`: Verification result (success/failed)
- `error`: Error message if applicable
- `headers`: SMTP debug logs
- `created_at`: Job submission timestamp
- `completed_at`: Job completion timestamp

## Performance Notes

- **Rate Limiting**: Enforces a global limit of 42 SMTP connections per minute
- **Caching**: SMTP capabilities are cached for 30 minutes per server
- **Concurrency**: Uses worker pool pattern with 4 workers by default
- **Database**: WAL mode enabled for better concurrent access

## Security Considerations

⚠️ **Warning**: This tool verifies email credentials by connecting to SMTP servers. Use responsibly and only with authorized credentials. Unauthorized testing of email addresses may violate terms of service or local laws.

## Dependencies

- `github.com/google/uuid`: UUID generation
- `github.com/gorilla/mux`: HTTP routing
- `github.com/mattn/go-sqlite3`: SQLite driver

## License

CC MIT