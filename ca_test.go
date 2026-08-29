// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCA_Generate(t *testing.T) {
	ca, err := GenerateCA(WithCASubject("acme test CA", "ACME"))
	require.NoError(t, err)

	cert := ca.Certificate()
	assert.True(t, cert.IsCA)
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign)
	assert.Equal(t, "acme test CA", cert.Subject.CommonName)
	assert.Equal(t, []string{"ACME"}, cert.Subject.Organization)
	assert.True(t, cert.BasicConstraintsValid)
	assert.NotEmpty(t, cert.SubjectKeyId)
	assert.True(t, cert.NotBefore.Before(time.Now()), "the certificate is backdated for clock skew")

	assert.Contains(t, string(ca.CertificatePEM()), "BEGIN CERTIFICATE")
	keyPEM, err := ca.PrivateKeyPEM()
	require.NoError(t, err)
	assert.Contains(t, string(keyPEM), "BEGIN PRIVATE KEY")
	assert.NotNil(t, ca.CertPool())
}

func TestCA_LeafIsSignedByTheAuthority(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	cert, err := ca.Leaf("api.stripe.com")
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)

	assert.Equal(t, []string{"api.stripe.com"}, cert.Leaf.DNSNames)
	assert.Equal(t, "api.stripe.com", cert.Leaf.Subject.CommonName)
	assert.Contains(t, cert.Leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.False(t, cert.Leaf.IsCA)
	assert.Len(t, cert.Certificate, 2, "the chain must carry the authority so a client can build it")

	// The leaf verifies against the authority for the name it was minted for, and not for
	// another.
	pool := ca.CertPool()
	_, err = cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "api.stripe.com"})
	require.NoError(t, err)
	_, err = cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "evil.test"})
	assert.Error(t, err)
}

func TestCA_LeafForAddressLiteral(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	require.Len(t, cert.Leaf.IPAddresses, 1)
	assert.True(t, cert.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")))
	assert.Empty(t, cert.Leaf.DNSNames)

	_, err = cert.Leaf.Verify(x509.VerifyOptions{Roots: ca.CertPool(), DNSName: "127.0.0.1"})
	assert.NoError(t, err)
}

func TestCA_LeafCache(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	first, err := ca.Leaf("api.test")
	require.NoError(t, err)
	second, err := ca.Leaf("API.TEST.")
	require.NoError(t, err)

	assert.Same(t, first, second,
		"a name differing only by case or a root label is the same name")

	other, err := ca.Leaf("other.test")
	require.NoError(t, err)
	assert.NotSame(t, first, other)

	_, err = ca.Leaf("")
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestCA_LeafTTL(t *testing.T) {
	ca, err := GenerateCA(WithLeafTTL(48 * time.Hour))
	require.NoError(t, err)

	cert, err := ca.Leaf("api.test")
	require.NoError(t, err)

	life := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	assert.Equal(t, 48*time.Hour+clockSkew, life)
}

func TestCA_LoadRoundTrip(t *testing.T) {
	original, err := GenerateCA(WithCASubject("round trip CA"))
	require.NoError(t, err)

	keyPEM, err := original.PrivateKeyPEM()
	require.NoError(t, err)

	loaded, err := LoadCA(original.CertificatePEM(), keyPEM)
	require.NoError(t, err)
	assert.Equal(t, original.Certificate().SerialNumber, loaded.Certificate().SerialNumber)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, os.WriteFile(certPath, original.CertificatePEM(), 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	fromFile, err := LoadCAFile(certPath, keyPath)
	require.NoError(t, err)
	assert.Equal(t, original.Certificate().SerialNumber, fromFile.Certificate().SerialNumber)

	_, err = LoadCAFile(filepath.Join(dir, "missing.pem"), keyPath)
	assert.Error(t, err)
	_, err = LoadCA([]byte("not pem"), keyPEM)
	assert.Error(t, err)
}

func TestCA_RejectsUnusableAuthorities(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	newCert := func(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}

	base := func() *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
		}
	}

	t.Run("nil certificate", func(t *testing.T) {
		_, err := NewCA(nil, key)
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})

	t.Run("nil key", func(t *testing.T) {
		tmpl := base()
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign
		_, err := NewCA(newCert(t, tmpl), nil)
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})

	t.Run("not a certificate authority", func(t *testing.T) {
		tmpl := base()
		tmpl.KeyUsage = x509.KeyUsageCertSign
		_, err := NewCA(newCert(t, tmpl), key)
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})

	t.Run("cannot sign certificates", func(t *testing.T) {
		tmpl := base()
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		_, err := NewCA(newCert(t, tmpl), key)
		assert.ErrorIs(t, err, ErrInvalidConfig)
		assert.Contains(t, err.Error(), "certificate signing")
	})

	t.Run("key does not match", func(t *testing.T) {
		tmpl := base()
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign
		cert := newCert(t, tmpl)

		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		_, err = NewCA(cert, other)
		assert.ErrorIs(t, err, ErrInvalidConfig)
		assert.Contains(t, err.Error(), "does not match")
	})
}

func TestCA_OptionValidation(t *testing.T) {
	for _, opt := range []CAOption{
		WithLeafCacheSize(0),
		WithLeafTTL(0),
		WithCAValidity(0),
		WithCASubject(""),
	} {
		_, err := GenerateCA(opt)
		assert.ErrorIs(t, err, ErrInvalidConfig)
	}
}

func TestCA_LeafRenewedBeforeItExpires(t *testing.T) {
	// A certificate inside the last tenth of its lifetime is renewed, so a connection
	// negotiated now is never handed one about to expire.
	fresh := &tlsCertStub{notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(10 * time.Hour)}
	stale := &tlsCertStub{notBefore: time.Now().Add(-10 * time.Hour), notAfter: time.Now().Add(30 * time.Minute)}

	assert.True(t, leafUsable(fresh.cert()))
	assert.False(t, leafUsable(stale.cert()))
	assert.False(t, leafUsable(nil))
}

type tlsCertStub struct {
	notBefore time.Time
	notAfter  time.Time
}

func (s *tlsCertStub) cert() *tls.Certificate {
	return &tls.Certificate{Leaf: &x509.Certificate{NotBefore: s.notBefore, NotAfter: s.notAfter}}
}
