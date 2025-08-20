// pkg/socks/server.go
package socks

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/jnovack/cache-server/pkg/ca"
	"github.com/jnovack/cache-server/pkg/cacheproxy"
)

// Server is a SOCKS5 server (no-auth) with HTTPS MITM support.
type Server struct {
	Addr     string
	CacheCfg cacheproxy.Config
	Metrics  interface {
		IncTotalRequests()
	}
	RootCA *ca.RootCA

	ln           net.Listener
	done         chan struct{}
	shutdownOnce sync.Once

	Capture *CaptureStore
}

// Start begins listening and serving until Close is called or listener fails.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.done = make(chan struct{})

	// ensure capture store exists and wire it as observer
	if s.Capture == nil {
		s.Capture = NewCaptureStore(1000)
	}
	// chain observer if existing
	prev := s.CacheCfg.RequestObserver
	if prev == nil {
		s.CacheCfg.RequestObserver = s.Capture.Add
	} else {
		s.CacheCfg.RequestObserver = func(r cacheproxy.RequestRecord) {
			prev(r)
			s.Capture.Add(r)
		}
	}

	go s.acceptLoop()
	log.Info().Str("addr", s.Addr).Msg("socks server started")
	return nil
}

// Close stops the listener and signals the accept loop to stop.
func (s *Server) Close() error {
	s.shutdownOnce.Do(func() {
		if s.ln != nil {
			_ = s.ln.Close()
		}
		if s.done != nil {
			close(s.done)
		}
	})
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				log.Debug().Err(err).Msg("listener closed, exiting accept loop")
				return
			default:
			}
			if strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "listener closed") {
				log.Debug().Err(err).Msg("listener closed, exiting accept loop")
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Warn().Err(err).Msg("temporary accept error, retrying")
				time.Sleep(50 * time.Millisecond)
				continue
			}
			log.Warn().Err(err).Msg("accept error")
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	// Greeting
	ver, err := br.ReadByte()
	if err != nil {
		return
	}
	if ver != 0x05 {
		return
	}
	nmeth, err := br.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, int(nmeth))
	if _, err := br.Read(methods); err != nil {
		return
	}
	// No authentication
	if _, err := bw.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	if err := bw.Flush(); err != nil {
		return
	}

	// Request
	ver, err = br.ReadByte()
	if err != nil || ver != 0x05 {
		return
	}
	cmd, err := br.ReadByte()
	if err != nil {
		return
	}
	_, _ = br.ReadByte() // RSV

	atyp, err := br.ReadByte()
	if err != nil {
		return
	}

	var host string
	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := br.Read(addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03: // Domain
		l, _ := br.ReadByte()
		name := make([]byte, int(l))
		if _, err := br.Read(name); err != nil {
			return
		}
		host = string(name)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := br.Read(addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		return
	}

	var port uint16
	if err := binary.Read(br, binary.BigEndian, &port); err != nil {
		return
	}

	// Only CONNECT supported.
	if cmd != 0x01 {
		_ = writeReply(bw, 0x07) // Command not supported
		return
	}

	// Reply success
	if err := writeReply(bw, 0x00); err != nil {
		return
	}

	// Decide path by port.
	switch port {
	case 80:
		cacheproxy.HandleHTTPOverConn(conn, br, s.CacheCfg)
		return
	case 443:
		cacheproxy.HandleMITMHTTPS(conn, host, s.CacheCfg)
		return
	default:
		// Plain TCP tunnel; attempt to parse initial bytes as HTTP for capture
		targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
		targetConn, err := net.DialTimeout("tcp", targetAddr, 15*time.Second)
		if err != nil {
			log.Error().Err(err).Str("target", targetAddr).Msg("failed to dial target for tunnel")
			return
		}
		defer targetConn.Close()

		peekReq, err := http.ReadRequest(br)
		if err == nil {
			// parsed HTTP request — capture and forward
			rawURL := "http://" + targetAddr + peekReq.URL.RequestURI()
			rec := cacheproxy.RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      peekReq.Method,
				Host:        targetAddr,
				Path:        peekReq.URL.RequestURI(),
				Outcome:     "TUNNEL_HTTP_REQUEST",
				IsTLS:       false,
				LatencySecs: 0,
				Size:        0,
				Status:      0,
			}
			// call observer synchronously (snapshot); notify is typically async but this is fine for tunnels
			if s.CacheCfg.RequestObserver != nil {
				s.CacheCfg.RequestObserver(rec)
			}
			if err := peekReq.Write(targetConn); err != nil {
				log.Error().Err(err).Msg("failed to forward parsed http request to target")
				return
			}
			go func() {
				_, _ = io.Copy(targetConn, br)
				_ = targetConn.Close()
			}()
			_, _ = io.Copy(conn, targetConn)
			return
		}

		// raw tunnel
		go func() {
			_, _ = io.Copy(targetConn, br)
			_ = targetConn.Close()
		}()
		_, _ = io.Copy(conn, targetConn)
		return
	}
}

func writeReply(bw *bufio.Writer, rep byte) error {
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := bw.Write(reply); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	return nil
}

// AttachCaptureStore allows attaching a capture store to the SOCKS server.
func (s *Server) AttachCaptureStore(cs *CaptureStore) {
	s.Capture = cs
}
