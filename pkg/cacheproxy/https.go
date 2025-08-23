package cacheproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// HandleHTTPS terminates TLS using a leaf cert obtained via cfg.RootCA.
// Certificate selection prefers the ClientHello SNI; if SNI is not present we
// fall back to the provided host parameter.
func HandleHTTPS(ctx context.Context, conn net.Conn, host string, cfg Config) {
	reqID := uuid.Must(uuid.NewV7()) // request_id
	ctx = context.WithValue(ctx, RequestIDKey{}, reqID)
	log.Ctx(ctx).Debug().
		Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
		Str("request_id", reqID.String()).
		Msg("handling HTTP over connection")
	defer func() { _ = conn.Close() }()

	if cfg.Metrics != nil {
		cfg.Metrics.IncTotalRequests()
	}

	// TLS specific checks
	if cfg.RootCA == nil {
		log.Ctx(ctx).Error().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Str("host", host).Msg("MITM requested but RootCA is nil")
		sendCustomError(conn, http.StatusInternalServerError, "Root CA not configured")
		return
	}

	// Use GetCertificate so we can inspect the ClientHello (SNI) and generate
	// a leaf certificate that matches the requested server name.
	tlsCfg := &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			serverName := chi.ServerName
			if serverName == "" {
				// fallback to the host passed by the caller (may be an IP)
				serverName = host
			}
			cert, err := cfg.RootCA.GetOrCreateLeaf(serverName)
			if err != nil {
				log.Ctx(ctx).Error().
					Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
					Str("request_id", reqID.String()).
					Err(err).Str("server_name", serverName).Msg("failed to GetOrCreateLeaf")
				return nil, err
			}
			return &cert, nil
		},
		NextProtos: []string{"http/1.1"},
	}

	tlsSrv := tls.Server(conn, tlsCfg)
	if err := tlsSrv.Handshake(); err != nil {
		// handshake may fail if the client does not speak TLS or disconnects
		log.Ctx(ctx).Debug().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Err(err).
			Str("host", host).
			Msg("TLS handshake with client failed")
		return
	}

	br := bufio.NewReader(tlsSrv)

	// Peek to check if there is any data after the TLS handshake
	// This is important to avoid blocking indefinitely on ReadRequest if the
	// client does not send any data.
	peek, err := br.Peek(1)
	if err != nil {
		if err != io.EOF {
			log.Ctx(ctx).Trace().
				Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
				Str("request_id", reqID.String()).
				Msg("error peeking post-TLS")
		}
		return // connection closed or peek failed — nothing to process
	}

	if len(peek) == 0 {
		// No data yet — either wait briefly or return immediately
		log.Ctx(ctx).Trace().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Msg("no request data after TLS handshake")
		return
	}

	// HTTP specific checks
	req, err := http.ReadRequest(br)
	if err != nil {
		if cfg.Metrics != nil {
			cfg.Metrics.IncOriginErrors()
		}
		log.Ctx(ctx).Debug().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Msg("failed to read HTTPS request from client")
		sendError(tlsSrv, http.StatusBadRequest)
		return
	}
	defer req.Body.Close()

	// Only GET and HEAD are cacheable in MITM path.
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		log.Ctx(ctx).Debug().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Str("method", req.Method).
			Msg("non-cacheable HTTPS method, denied in MITM mode")
		sendError(tlsSrv, http.StatusMethodNotAllowed)
		return
	}

	// At this point we have a valid GET/HEAD request over TLS, so we can
	// proceed to handle it via the common cache handling logic.
	HandleCacheRequest(ctx, tlsSrv, req, cfg, true)
}
