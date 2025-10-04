# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o main .

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates sqlite-libs tzdata

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

# Run the application
CMD ["./main"]

