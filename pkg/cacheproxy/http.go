package cacheproxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// file locks to avoid concurrent writes to same cache path.
var locks sync.Map // map[string]*sync.Mutex

// HandleHTTP reads a single HTTP request from br (wrapping conn), processes
// caching logic and writes back the HTTP response over conn. This is used by the socks code.
func HandleHTTP(ctx context.Context, conn net.Conn, host string, cfg Config) {
	reqID := uuid.Must(uuid.NewV7()) // request_id
	ctx = context.WithValue(ctx, RequestIDKey{}, reqID)
	if cfg.Metrics != nil {
		cfg.Metrics.IncTotalRequests()
	}

	br := bufio.NewReader(conn)

	// HTTP specific checks
	req, err := http.ReadRequest(br)
	if err != nil {
		if cfg.Metrics != nil {
			cfg.Metrics.IncOriginErrors()
		}
		log.Ctx(ctx).Debug().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Err(err).
			Msg("failed to read HTTP request from connection")
		sendError(conn, http.StatusBadRequest)
		return
	}
	defer req.Body.Close()

	// Only GET and HEAD are cacheable; others are proxied (simple tunnel)
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		target := req.Host
		if !strings.Contains(target, ":") {
			target = net.JoinHostPort(target, "80")
		}
		server, err := net.DialTimeout("tcp", target, 15*time.Second)
		if err != nil {
			if cfg.Metrics != nil {
				cfg.Metrics.IncOriginErrors()
			}
			log.Ctx(ctx).Error().
				Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
				Str("request_id", reqID.String()).
				Err(err).
				Str("target", target).
				Msg("failed to dial origin for non-GET/HEAD")
			sendError(conn, http.StatusBadGateway)
			return
		}
		defer server.Close()
		_ = req.Write(server)
		_ = proxyCopy(conn, server)
		return
	}

	log.Ctx(ctx).Debug().
		Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
		Str("request_id", reqID.String()).
		Msg("handling HTTP")

	// Use common caching logic
	HandleCacheRequest(ctx, conn, req, cfg, false)

}
