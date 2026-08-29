// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fox-toolkit/edge/internal/simplelru"
	"github.com/fox-toolkit/edge/internal/stringsutil"
)

const (
	defaultLeafCacheSize = 1024
	defaultLeafTTL       = 7 * 24 * time.Hour
	defaultCATTL         = 10 * 365 * 24 * time.Hour
	// clockSkew backdates a minted certificate so a client whose clock runs slightly ahead
	// of the proxy still accepts it.
	clockSkew = time.Hour
)

// CA is the certificate authority the proxy signs intercepted authorities with. Leaf
// certificates are minted on demand and cached, and every leaf shares one key pair: the
// expensive half of minting is key generation, and reusing the key makes a cache miss cost
// a single signature.
//
// A CA is safe for concurrent use.
type CA struct {
	key crypto.Signer

	leafKey  crypto.Signer
	cert     *x509.Certificate
	cache    *simplelru.LRU[string, *tls.Certificate]
	inflight map[string]*mintCall
	certDER  []byte

	leafPubDER []byte
	leafTTL    time.Duration

	mu sync.Mutex
}

type mintCall struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

type caConfig struct {
	commonName   string
	organization []string
	cacheSize    int
	leafTTL      time.Duration
	caTTL        time.Duration
}

// CAOption configures a [CA].
type CAOption interface {
	applyCA(*caConfig) error
}

type caOptionFunc func(*caConfig) error

func (f caOptionFunc) applyCA(c *caConfig) error { return f(c) }

// WithLeafCacheSize bounds how many minted leaf certificates are kept. It defaults to 1024.
func WithLeafCacheSize(n int) CAOption {
	return caOptionFunc(func(c *caConfig) error {
		if n <= 0 {
			return fmt.Errorf("%w: leaf cache size must be greater than zero", ErrInvalidConfig)
		}
		c.cacheSize = n
		return nil
	})
}

// WithLeafTTL sets how long a minted leaf certificate is valid. It defaults to 7 days.
func WithLeafTTL(d time.Duration) CAOption {
	return caOptionFunc(func(c *caConfig) error {
		if d <= 0 {
			return fmt.Errorf("%w: leaf TTL must be greater than zero", ErrInvalidConfig)
		}
		c.leafTTL = d
		return nil
	})
}

// WithCAValidity sets how long a CA created by [GenerateCA] is valid. It defaults to 10 years.
func WithCAValidity(d time.Duration) CAOption {
	return caOptionFunc(func(c *caConfig) error {
		if d <= 0 {
			return fmt.Errorf("%w: CA validity must be greater than zero", ErrInvalidConfig)
		}
		c.caTTL = d
		return nil
	})
}

// WithCASubject sets the common name and organization of a CA created by [GenerateCA].
func WithCASubject(commonName string, organization ...string) CAOption {
	return caOptionFunc(func(c *caConfig) error {
		if commonName == "" {
			return fmt.Errorf("%w: CA common name cannot be empty", ErrInvalidConfig)
		}
		c.commonName = commonName
		c.organization = organization
		return nil
	})
}

func newCAConfig() *caConfig {
	return &caConfig{
		cacheSize:    defaultLeafCacheSize,
		leafTTL:      defaultLeafTTL,
		caTTL:        defaultCATTL,
		commonName:   "edge proxy CA",
		organization: []string{"edge"},
	}
}

// NewCA returns a [CA] signing with cert and key. cert must be a certificate authority with
// the certificate signing key usage, otherwise clients reject every leaf it issues.
func NewCA(cert *x509.Certificate, key crypto.Signer, opts ...CAOption) (*CA, error) {
	if cert == nil {
		return nil, fmt.Errorf("%w: nil certificate", ErrInvalidConfig)
	}
	if key == nil {
		return nil, fmt.Errorf("%w: nil private key", ErrInvalidConfig)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%w: certificate is not a certificate authority", ErrInvalidConfig)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%w: certificate is missing the certificate signing key usage", ErrInvalidConfig)
	}
	if !publicKeyMatches(cert.PublicKey, key.Public()) {
		return nil, fmt.Errorf("%w: private key does not match the certificate", ErrInvalidConfig)
	}

	cfg := newCAConfig()
	for _, opt := range opts {
		if err := opt.applyCA(cfg); err != nil {
			return nil, err
		}
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	leafPubDER, err := x509.MarshalPKIXPublicKey(leafKey.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal leaf public key: %w", err)
	}

	cache, err := simplelru.NewLRU[string, *tls.Certificate](cfg.cacheSize, nil)
	if err != nil {
		return nil, fmt.Errorf("create leaf cache: %w", err)
	}

	return &CA{
		cert:       cert,
		key:        key,
		certDER:    cert.Raw,
		leafKey:    leafKey,
		leafPubDER: leafPubDER,
		leafTTL:    cfg.leafTTL,
		cache:      cache,
		inflight:   make(map[string]*mintCall),
	}, nil
}

// LoadCA returns a [CA] from a PEM encoded certificate and private key.
func LoadCA(certPEM, keyPEM []byte, opts ...CAOption) (*CA, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("%w: no certificate in PEM block", ErrInvalidConfig)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: CA private key does not implement crypto.Signer", ErrInvalidConfig)
	}
	return NewCA(cert, key, opts...)
}

// LoadCAFile returns a [CA] from a PEM encoded certificate and private key on disk.
func LoadCAFile(certPath, keyPath string, opts ...CAOption) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	return LoadCA(certPEM, keyPEM, opts...)
}

// GenerateCA creates a new self-signed certificate authority. It is meant for tests and for
// bootstrapping a local setup: export it with [CA.CertificatePEM] and [CA.PrivateKeyPEM] and
// install it in the trust store of whatever is being proxied.
func GenerateCA(opts ...CAOption) (*CA, error) {
	cfg := newCAConfig()
	for _, opt := range opts {
		if err := opt.applyCA(cfg); err != nil {
			return nil, err
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	skid, err := subjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cfg.commonName,
			Organization: cfg.organization,
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(cfg.caTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          skid,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}

	return NewCA(cert, key, opts...)
}

// Certificate returns the CA certificate.
func (ca *CA) Certificate() *x509.Certificate { return ca.cert }

// CertificatePEM returns the PEM encoding of the CA certificate, ready to be installed in a
// trust store.
func (ca *CA) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certDER})
}

// PrivateKeyPEM returns the PKCS#8 PEM encoding of the CA private key.
func (ca *CA) PrivateKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// CertPool returns a pool holding only the CA certificate, for a client that should trust
// the proxy and nothing else.
func (ca *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// Leaf returns a certificate for host, minting and caching one on the first call. host is a
// hostname or an IP literal, without a port.
func (ca *CA) Leaf(host string) (*tls.Certificate, error) {
	key := leafCacheKey(host)
	if key == "" {
		return nil, fmt.Errorf("%w: empty host", ErrInvalidConfig)
	}

	ca.mu.Lock()
	if cert, ok := ca.cache.Get(key); ok && leafUsable(cert) {
		ca.mu.Unlock()
		return cert, nil
	}
	if call, ok := ca.inflight[key]; ok {
		// Another goroutine is already minting this leaf. Wait for it instead of signing
		// the same certificate twice.
		ca.mu.Unlock()
		<-call.done
		return call.cert, call.err
	}
	call := &mintCall{done: make(chan struct{})}
	ca.inflight[key] = call
	ca.mu.Unlock()

	call.cert, call.err = ca.mint(host)

	ca.mu.Lock()
	if call.err == nil {
		ca.cache.Add(key, call.cert)
	}
	delete(ca.inflight, key)
	ca.mu.Unlock()

	close(call.done)
	return call.cert, call.err
}

func (ca *CA) mint(host string) (*tls.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(ca.leafTTL),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		// A certificate for an IP has no meaningful common name, and some stacks reject a
		// CN that is not a DNS name.
		tmpl.Subject.CommonName = ip.String()
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, ca.leafKey.Public(), ca.key)
	if err != nil {
		return nil, fmt.Errorf("mint leaf certificate for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse minted certificate for %s: %w", host, err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der, ca.certDER},
		PrivateKey:  ca.leafKey,
		Leaf:        leaf,
	}, nil
}

// leafUsable reports whether a cached certificate is still worth serving. A leaf is renewed
// once it is inside the last tenth of its lifetime, so a long-lived connection never
// negotiates with a certificate about to expire.
func leafUsable(cert *tls.Certificate) bool {
	if cert == nil || cert.Leaf == nil {
		return false
	}
	life := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	return time.Now().Before(cert.Leaf.NotAfter.Add(-life / 10))
}

// leafCacheKey normalizes host into a cache key. Hostnames are compared case-insensitively
// and a trailing root label is not part of the name.
func leafCacheKey(host string) string {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return stringsutil.ToLowerASCIIString(host)
}

func randomSerial() (*big.Int, error) {
	// 128 random bits, the same entropy public CAs are required to use.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return sum[:20], nil
}

func publicKeyMatches(certPub, keyPub crypto.PublicKey) bool {
	type equaler interface{ Equal(x crypto.PublicKey) bool }
	eq, ok := certPub.(equaler)
	return ok && eq.Equal(keyPub)
}

var errNoCA = errors.New("interception requires a certificate authority")
