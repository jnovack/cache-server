package socks

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jnovack/cache-server/pkg/cacheproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// socks5Connect is a small helper that performs a minimal SOCKS5 no-auth
// handshake and CONNECT to the requested host:port. If useDomain is true,
// it sends ATYP=DOMAIN; otherwise it sends ATYP=IPv4 with the provided host.
func socks5Connect(t *testing.T, proxyAddr, host string, port uint16, useDomain bool) net.Conn {
	t.Helper()

	c, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err, "dial proxy")

	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)

	// Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
	_, _ = bw.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, bw.Flush(), "flush greeting")

	// Method selection reply
	ver, err := br.ReadByte()
	require.NoError(t, err, "read ver")
	require.Equal(t, byte(0x05), ver, "socksv")

	meth, err := br.ReadByte()
	require.NoError(t, err, "read method")
	require.Equal(t, byte(0x00), meth, "no-auth method")

	// CONNECT request header
	_, _ = bw.Write([]byte{0x05, 0x01, 0x00}) // VER=5, CMD=CONNECT, RSV=0

	// Address
	if useDomain {
		hb := []byte(host)
		_, _ = bw.Write([]byte{0x03, byte(len(hb))}) // ATYP=DOMAIN, length
		_, _ = bw.Write(hb)
	} else {
		ip := net.ParseIP(host).To4()
		require.NotNil(t, ip, "expected ipv4 address when useDomain=false")
		_, _ = bw.Write([]byte{0x01}) // ATYP=IPv4
		_, _ = bw.Write(ip)
	}

	// Port
	require.NoError(t, binary.Write(bw, binary.BigEndian, port), "write port")
	require.NoError(t, bw.Flush(), "flush connect")

	// Reply: VER, REP, RSV, ATYP, BND.ADDR..., BND.PORT...
	reply := make([]byte, 10)
	_, err = io.ReadFull(br, reply)
	require.NoError(t, err, "read connect reply")
	require.Equal(t, byte(0x00), reply[1], "rep success")

	return c
}

func TestSOCKS_DomainATYP_HTTPFlow(t *testing.T) {
	// Origin HTTP server.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok-domain")
	}))
	defer origin.Close()

	originURL := strings.TrimPrefix(origin.URL, "http://")
	parts := strings.Split(originURL, ":")
	require.Len(t, parts, 2, "unexpected origin url")

	host := "localhost"
	portNum, _ := strconv.Atoi(parts[1])

	// Start SOCKS server.
	s := &Server{
		Addr: "127.0.0.1:0",
		CacheCfg: cacheproxy.Config{
			CacheDir: t.TempDir(),
		},
	}
	require.NoError(t, s.Start(), "start socks")
	defer s.Close()

	// Connect via SOCKS using DOMAIN atyp (localhost).
	conn := socks5Connect(t, s.ln.Addr().String(), host, uint16(portNum), true)
	defer conn.Close()

	// Speak HTTP over the established tunnel.
	req := "GET / HTTP/1.1\r\nHost: " + originURL + "\r\nConnection: close\r\n\r\n"
	_, err := io.WriteString(conn, req)
	require.NoError(t, err, "write http request")

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err, "read response")
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "ok-domain", string(body), "unexpected body")

	// Ensure capture store recorded something.
	time.Sleep(100 * time.Millisecond)
	entries := s.Capture.List()
	require.NotEmpty(t, entries, "expected at least one captured entry")
}

func TestSOCKS_IPv4ATYP_HTTPFlow(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok-ip")
	}))
	defer origin.Close()

	originURL := strings.TrimPrefix(origin.URL, "http://")
	parts := strings.Split(originURL, ":")
	require.Len(t, parts, 2, "unexpected origin url")

	ip := "127.0.0.1"
	portNum, _ := strconv.Atoi(parts[1])

	s := &Server{
		Addr: "127.0.0.1:0",
		CacheCfg: cacheproxy.Config{
			CacheDir: t.TempDir(),
		},
	}
	require.NoError(t, s.Start(), "start socks")
	defer s.Close()

	conn := socks5Connect(t, s.ln.Addr().String(), ip, uint16(portNum), false)
	defer conn.Close()

	req := "GET / HTTP/1.1\r\nHost: " + originURL + "\r\nConnection: close\r\n\r\n"
	_, err := io.WriteString(conn, req)
	require.NoError(t, err, "write http request")

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err, "read resp")
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "ok-ip", string(body), "unexpected body")

	time.Sleep(100 * time.Millisecond)
	entries := s.Capture.List()
	require.NotEmpty(t, entries, "expected captured entries")
}

func TestAttachCaptureStore_ChainsAndCaptures(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "capture-me")
	}))
	defer origin.Close()

	originURL := strings.TrimPrefix(origin.URL, "http://")
	parts := strings.Split(originURL, ":")
	require.Len(t, parts, 2, "unexpected origin url")

	host := "localhost"
	portNum, _ := strconv.Atoi(parts[1])

	// Prepare an external capture store and attach it.
	external := NewCaptureStore(32)

	s := &Server{
		Addr: "127.0.0.1:0",
		CacheCfg: cacheproxy.Config{
			CacheDir: t.TempDir(),
		},
	}
	// Attach before Start() to verify chaining still works when Start sets up its own capture.
	s.AttachCaptureStore(external)

	require.NoError(t, s.Start(), "start socks")
	defer s.Close()

	conn := socks5Connect(t, s.ln.Addr().String(), host, uint16(portNum), true)
	defer conn.Close()

	req := "GET /x HTTP/1.1\r\nHost: " + originURL + "\r\nConnection: close\r\n\r\n"
	_, err := io.WriteString(conn, req)
	require.NoError(t, err, "write http request")

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err, "read resp")
	_ = resp.Body.Close()

	// Allow observer to run.
	time.Sleep(150 * time.Millisecond)

	// Both internal and external capture stores should have entries.
	internal := s.Capture.List()
	ext := external.List()

	require.NotEmpty(t, internal, "internal capture store empty")
	require.NotEmpty(t, ext, "external capture store empty")

	// Spot-check path presence in external store.
	found := false
	for _, r := range ext {
		if strings.Contains(r.Path, "/x") || strings.Contains(r.URL, "/x") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected to find /x in external captures")
}
