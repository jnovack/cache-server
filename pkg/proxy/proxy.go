// Package proxy exposes small interfaces used by cmd binaries to interact with cache & CA packages.
//
// It intentionally keeps implementation details out of the interface so that the cmd layer
// can wire concrete implementations (e.g., using pkg/ca, pkg/cache, pkg/admin).
package proxy

import (
	"crypto/tls"
	"net/url"
)

// CacheStore is the minimal abstraction for file-backed caching used by the proxy.
type CacheStore interface {
	// CachePathFor returns the filesystem path and meta path used for storing u.
	CachePathFor(u *url.URL) (filePath string, metaPath string)

	// ReadMeta returns cached metadata for the given metaPath.
	ReadMeta(metaPath string) (interface{}, error)

	// WriteMeta stores metadata (opaque) for the given metaPath.
	WriteMeta(metaPath string, meta interface{}) error
}

// CertProvider returns TLS certificates suitable for acting as server towards clients.
type CertProvider interface {
	// GetCert returns a tls.Certificate for the given host (SNI).
	GetCert(host string) (tls.Certificate, error)
}
