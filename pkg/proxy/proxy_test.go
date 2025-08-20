package proxy_test

import (
	"net/url"
	"testing"

	"github.com/jnovack/cache-server/pkg/proxy"
)

// mockCache is a trivial implementation of the CacheStore interface for compile-time check.
type mockCache struct{}

func (m *mockCache) CachePathFor(u *url.URL) (string, string) {
	return "/tmp/fakepath", "/tmp/fakemeta"
}
func (m *mockCache) ReadMeta(metaPath string) (interface{}, error) {
	return nil, nil
}
func (m *mockCache) WriteMeta(metaPath string, meta interface{}) error {
	return nil
}

type mockCertProvider struct{}

func (m *mockCertProvider) GetCert(host string) (cert interface{}, err error) {
	return nil, nil
}

func TestInterfacesImplemented(t *testing.T) {
	var _ proxy.CacheStore = (*mockCache)(nil)
	// CertProvider in the actual package expects tls.Certificate; proxied test ensures type relation compile-time only
}
