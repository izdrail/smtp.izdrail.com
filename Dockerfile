# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies for CGO
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application with CGO enabled (required for sqlite3)
RUN CGO_ENABLED=1 GOOS=linux go build -o smtp-verifier verify.go

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/smtp-verifier .
COPY --from=builder /app/index.html .

# Set default environment variables
ENV PORT=1240
ENV DB_PATH=/app/data/scans.db

# Create data directory for persistence
RUN mkdir -p /app/data

# Expose the application port
EXPOSE 1240

# Run the application
CMD ["./smtp-verifier"]
