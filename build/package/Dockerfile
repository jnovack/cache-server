# Stage 1: Build the Go binary
FROM golang:1.25 AS builder

WORKDIR /app

# Leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 go build -v -o cache-server ./cmd/cache-server

# Stage 2: Minimal runtime image
FROM gcr.io/distroless/static:nonroot

# Set environment variable (can be overridden at runtime)
ENV DOMAIN=contoso.local

# Copy the binary
COPY --from=builder /app/cache-server /

# Healthcheck on /healthz
# HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
# CMD [ "wget", "--spider", "-q", "http://localhost:8080/healthz" ]

# Expose port 8080
EXPOSE 8080

# Declare /cache as a mountable volume
VOLUME ["/cache"]

# Run the binary with the domain flag
ENTRYPOINT ["/cache-server"]
