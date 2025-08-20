// Package ca implements root CA and per-host leaf certificate generation and on-disk caching.
//
// Responsibilities:
//   - Parse a DN (flexible formats) into pkix.Name
//   - Load a root CA from combined PEM or separate cert/key files
//   - Generate a self-signed root CA when requested (or by default if none provided)
//   - Create per-host leaf certificates signed by the root CA and cache them on disk
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RootCA holds a parsed root certificate, the private key and the combined PEM bytes.
type RootCA struct {
	Cert     *x509.Certificate
	Priv     crypto.PrivateKey
	pem      []byte
	CacheDir string // directory where leaf certs will be stored (certs/)
}

// PEM returns the PEM-encoded root certificate bytes as a getter function.
func (r *RootCA) PEM() []byte {
	return r.pem // assuming field is lowercase "pem" or change accordingly
}

// CheckPEMHasCertAndKey checks combined PEM bytes contains at least one CERTIFICATE and one PRIVATE KEY block.
func CheckPEMHasCertAndKey(pemBytes []byte) (hasCert bool, hasKey bool) {
	remain := pemBytes
	for {
		var block *pem.Block
		block, remain = pem.Decode(remain)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			hasCert = true
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			hasKey = true
		}
	}
	return
}

// LoadCombinedRoot loads a combined PEM (certificate + private key) and returns a RootCA.
func LoadCombinedRoot(pemBytes []byte, cacheDir string) (*RootCA, error) {
	// Verify has both pieces
	hasCert, hasKey := CheckPEMHasCertAndKey(pemBytes)
	if !hasCert || !hasKey {
		return nil, fmt.Errorf("combined PEM missing certificate or private key")
	}

	// Parse certificate (first CERTIFICATE block)
	var cert *x509.Certificate
	var key crypto.PrivateKey
	remain := pemBytes
	for {
		var block *pem.Block
		block, remain = pem.Decode(remain)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing certificate block: %w", err)
			}
			cert = c
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
			}
			key = k
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing RSA private key: %w", err)
			}
			key = k
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing EC private key: %w", err)
			}
			key = k
		}
	}

	if cert == nil || key == nil {
		return nil, errors.New("combined PEM did not yield both certificate and key")
	}

	return &RootCA{Cert: cert, Priv: key, pem: pemBytes, CacheDir: cacheDir}, nil
}

// SaveCombined writes the combined PEM to disk atomically.
func (r *RootCA) SaveCombined(path string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, r.PEM(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SaveKeyBlock writes the private key-only PEM (extracted from combined PEM) to disk.
func (r *RootCA) SaveKeyBlock(path string) error {
	// Extract first PRIVATE KEY block from PEM
	remain := r.PEM()
	for {
		var block *pem.Block
		block, remain = pem.Decode(remain)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			b := pem.EncodeToMemory(block)
			tmp := path + ".tmp"
			if err := os.WriteFile(tmp, b, 0o600); err != nil {
				return err
			}
			return os.Rename(tmp, path)
		}
	}
	return errors.New("no private key block found in combined PEM")
}

// ParseDN parses a flexible DN string into pkix.Name.
// Supported formats:
//   - plain string without '=' -> treated as CommonName
//   - slash-style:  "/C=US/ST=.../O=Org/CN=Name"
//   - comma/semicolon style: "CN=Name,O=Org,C=US"
func ParseDN(s string) (pkix.Name, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return pkix.Name{}, errors.New("empty dn")
	}
	// if no '=' treat as CN only
	if !strings.Contains(s, "=") {
		return pkix.Name{CommonName: s}, nil
	}
	parts := splitDN(s)
	name := pkix.Name{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToUpper(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		switch k {
		case "CN":
			name.CommonName = v
		case "O":
			name.Organization = append(name.Organization, v)
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, v)
		case "L":
			name.Locality = append(name.Locality, v)
		case "ST", "S":
			name.Province = append(name.Province, v)
		case "C":
			name.Country = append(name.Country, v)
		default:
			// ignore unknown attributes
		}
	}
	if name.CommonName == "" {
		return name, errors.New("dn must include CN")
	}
	return name, nil
}

func splitDN(s string) []string {
	if strings.HasPrefix(s, "/") {
		s = strings.TrimPrefix(s, "/")
		return strings.Split(s, "/")
	}
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';'
	})
}

// GenerateRootCASelfSigned generates an RSA-4096 self-signed root certificate for the provided pkix.Name.
func GenerateRootCASelfSigned(name pkix.Name) (*RootCA, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate root RSA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               name,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create root certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated certificate: %w", err)
	}
	combined := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})...)
	return &RootCA{Cert: cert, Priv: priv, pem: combined}, nil
}

// NewRootCAFromFiles tries to load root CA from combined PEM (rootPem) or separate cert/key files.
// If none provided (empty strings), returns nil nil (caller may choose to generate default).
func NewRootCAFromFiles(rootPem, rootCert, rootKey string, cacheDir string) (*RootCA, error) {
	if rootPem != "" {
		b, err := os.ReadFile(rootPem)
		if err != nil {
			return nil, fmt.Errorf("read root-pem: %w", err)
		}
		return LoadCombinedRoot(b, cacheDir)
	}
	if rootCert != "" && rootKey != "" {
		cb, err := os.ReadFile(rootCert)
		if err != nil {
			return nil, fmt.Errorf("read root-cert: %w", err)
		}
		kb, err := os.ReadFile(rootKey)
		if err != nil {
			return nil, fmt.Errorf("read root-key: %w", err)
		}
		combined := append(cb, kb...)
		return LoadCombinedRoot(combined, cacheDir)
	}
	return nil, errors.New("no root CA files provided")
}

// GetOrCreateLeaf generates (or loads cached) per-host leaf certificate signed by the root CA.
// Leaf certs are cached under <r.CacheDir>/certs/<host>.pem (combined leaf cert + private key).
func (r *RootCA) GetOrCreateLeaf(host string) (tls.Certificate, error) {
	if r == nil {
		return tls.Certificate{}, errors.New("root CA is nil")
	}
	cacheDir := r.CacheDir
	if cacheDir == "" {
		cacheDir = "./cache"
	}
	ensure := filepath.Join(cacheDir, "certs")
	_ = os.MkdirAll(ensure, 0o755)
	cleanHost := strings.ReplaceAll(host, ":", "_")
	path := filepath.Join(ensure, cleanHost+".pem")

	// Try load from disk
	if b, err := os.ReadFile(path); err == nil {
		if cert, err := tls.X509KeyPair(b, b); err == nil {
			return cert, nil
		}
		// else fall through to regenerate
	}

	// Generate new leaf
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.AddDate(1, 0, 0)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// set SANs
	hostOnly := host
	if strings.Contains(hostOnly, ":") {
		if h, _, err := net.SplitHostPort(hostOnly); err == nil {
			hostOnly = h
		}
	}
	if ip := net.ParseIP(hostOnly); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostOnly}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, r.Cert, &priv.PublicKey, r.Priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	combined := append(leafPem, keyPem...)

	// persist atomically
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, combined, 0o600); err == nil {
		_ = os.Rename(tmp, path)
	} // on failure, still proceed to use in-memory bytes

	cert, err := tls.X509KeyPair(combined, combined)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}
