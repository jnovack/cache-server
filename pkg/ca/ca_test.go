package ca

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseDNVarious covers plain CN, slash-style and comma-style DNs.
func TestParseDNVarious(t *testing.T) {
	cases := []struct {
		in string
		cn string
	}{
		{"SimpleCN", "SimpleCN"},
		{"/C=US/ST=CA/O=Org/OU=Unit/CN=My CA", "My CA"},
		{"CN=My CA,O=Org,C=US", "My CA"},
		{"CN=Only", "Only"},
		{"CN=Name;O=Org;C=NZ", "Name"},
	}
	for _, c := range cases {
		n, err := ParseDN(c.in)
		if err != nil {
			t.Fatalf("ParseDN(%q) returned error: %v", c.in, err)
		}
		if n.CommonName != c.cn {
			t.Fatalf("ParseDN(%q): expected CN %q, got %q", c.in, c.cn, n.CommonName)
		}
	}
}

// TestGenerateRootAndSaveLoad verifies root generation and saving/loading combined PEM.
func TestGenerateRootAndSaveLoad(t *testing.T) {
	td := t.TempDir()

	// Generate root
	name, _ := ParseDN("Unit Test Root")
	rc, err := GenerateRootCASelfSigned(name)
	if err != nil {
		t.Fatalf("GenerateRootCASelfSigned error: %v", err)
	}
	if rc.Cert == nil || rc.Priv == nil || len(rc.PEM()) == 0 {
		t.Fatalf("incomplete RootCA generated")
	}

	// Save combined PEM to disk and key-only block
	combinedPath := filepath.Join(td, "root_combined.pem")
	keyPath := filepath.Join(td, "root_key.pem")
	if err := os.WriteFile(combinedPath+".tmp", rc.PEM(), 0o600); err != nil {
		t.Fatalf("writing tmp combined failed: %v", err)
	}
	if err := os.Rename(combinedPath+".tmp", combinedPath); err != nil {
		t.Fatalf("rename tmp: %v", err)
	}

	// Extract key block and write
	remain := rc.PEM()
	var keyBlock *pem.Block
	for {
		var b *pem.Block
		b, remain = pem.Decode(remain)
		if b == nil {
			break
		}
		if b.Type == "RSA PRIVATE KEY" || strings.Contains(b.Type, "PRIVATE KEY") {
			keyBlock = b
			break
		}
	}
	if keyBlock == nil {
		t.Fatalf("failed to find private key block in generated PEM")
	}
	if err := os.WriteFile(keyPath+".tmp", pem.EncodeToMemory(keyBlock), 0o600); err != nil {
		t.Fatalf("write key tmp: %v", err)
	}
	if err := os.Rename(keyPath+".tmp", keyPath); err != nil {
		t.Fatalf("rename key tmp: %v", err)
	}

	// Load combined root with LoadCombinedRoot (use bytes)
	loaded, err := LoadCombinedRoot(rc.PEM(), td)
	if err != nil {
		t.Fatalf("LoadCombinedRoot failed: %v", err)
	}
	if loaded.Cert.Subject.CommonName != "Unit Test Root" {
		t.Fatalf("unexpected CN after load: %q", loaded.Cert.Subject.CommonName)
	}
}

// TestLeafCache ensures GetOrCreateLeaf creates and caches leaf certificate file.
func TestGetOrCreateLeafCaching(t *testing.T) {
	td := t.TempDir()
	name, _ := ParseDN("Leaf Root")
	rc, err := GenerateRootCASelfSigned(name)
	if err != nil {
		t.Fatalf("generate root: %v", err)
	}
	rc.CacheDir = td

	// Create leaf
	host := "example.local"
	cert1, err := rc.GetOrCreateLeaf(host)
	if err != nil {
		t.Fatalf("GetOrCreateLeaf failed: %v", err)
	}
	if len(cert1.Certificate) == 0 {
		t.Fatalf("generated leaf has empty certificate array")
	}

	// Ensure file exists
	cp := filepath.Join(td, "certs", "example.local.pem")
	if _, err := os.Stat(cp); err != nil {
		t.Fatalf("expected cached leaf file at %s: %v", cp, err)
	}

	// Second call should load from cache
	cert2, err := rc.GetOrCreateLeaf(host)
	if err != nil {
		t.Fatalf("second GetOrCreateLeaf failed: %v", err)
	}
	if len(cert2.Certificate) == 0 {
		t.Fatalf("cached leaf parse produced empty certificates")
	}

	// Sanity: parse the cached pem and ensure it contains a certificate block
	b, _ := os.ReadFile(cp)
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("cached leaf pem does not decode")
	}
	// Parse certificate as extra sanity
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("parse cert from cached pem failed: %v", err)
	}
}

func TestLeafSANIncludesIP(t *testing.T) {
	name, _ := ParseDN("CN=TestRoot")
	root, err := GenerateRootCASelfSigned(name)
	if err != nil {
		t.Fatalf("GenerateRootCA error: %v", err)
	}
	root.CacheDir = t.TempDir()

	cert, err := root.GetOrCreateLeaf("203.0.113.100")
	if err != nil {
		t.Fatalf("GetOrCreateLeaf failed: %v", err)
	}
	// Parse cert to x509
	x, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	found := false
	for _, ip := range x.IPAddresses {
		if ip.Equal(net.ParseIP("203.0.113.100")) {
			found = true
		}
	}
	if !found {
		t.Fatal("expected SAN IP 203.0.113.100")
	}
}
