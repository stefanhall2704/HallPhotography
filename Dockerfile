# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies (no SQLite needed anymore)
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Set working directory
WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/main .

# Copy templates, static files, and other necessary directories
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/calendar ./calendar

# Create necessary directories for persistent data
RUN mkdir -p uploads/profile_pictures uploads/session_photos downloads

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider https://localhost:8080/ || exit 1

# Run the application
CMD ["./main"]

