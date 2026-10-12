package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTLSReloaderFollowsKubernetesSecretUpdate(t *testing.T) {
	dir := t.TempDir()

	// Kubernetes mounts a Secret as symlinks that point through ..data into a timestamped
	// directory, and publishes an update by atomically renaming a new ..data symlink.
	// The tls.crt and tls.key symlinks themselves never change.
	first := filepath.Join(dir, "..2026_01_01_00_00_00.000000001")
	require.NoError(t, os.Mkdir(first, 0o700))
	writeTestKeyPair(t, first, "first")
	require.NoError(t, os.Symlink(filepath.Base(first), filepath.Join(dir, "..data")))
	for _, name := range []string{"tls.crt", "tls.key"} {
		require.NoError(t, os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)))
	}

	cfg, err := newTLSReloader(slog.New(slog.DiscardHandler), filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), "", &tls.Config{})
	require.NoError(t, err)
	addr := serveTLS(t, cfg)
	requireServedCommonName(t, addr, "first")

	second := filepath.Join(dir, "..2026_01_01_00_00_00.000000002")
	require.NoError(t, os.Mkdir(second, 0o700))
	writeTestKeyPair(t, second, "second")
	require.NoError(t, os.Symlink(filepath.Base(second), filepath.Join(dir, "..data_tmp")))
	require.NoError(t, os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")))

	requireEventuallyServed(t, addr, "second")
}

func TestTLSReloaderFollowsInPlaceWrite(t *testing.T) {
	dir := t.TempDir()
	writeTestKeyPair(t, dir, "first")

	cfg, err := newTLSReloader(slog.New(slog.DiscardHandler), filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), "", &tls.Config{})
	require.NoError(t, err)
	addr := serveTLS(t, cfg)
	requireServedCommonName(t, addr, "first")

	// Overwriting the existing files produces write events, not create events.
	writeTestKeyPair(t, dir, "second")

	requireEventuallyServed(t, addr, "second")
}

func TestTLSReloaderKeepsCertificateWhenReloadFails(t *testing.T) {
	dir := t.TempDir()
	writeTestKeyPair(t, dir, "first")

	logs := &lockedBuffer{}
	cfg, err := newTLSReloader(slog.New(slog.NewTextHandler(logs, nil)), filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), "", &tls.Config{})
	require.NoError(t, err)
	addr := serveTLS(t, cfg)
	requireServedCommonName(t, addr, "first")

	tmp := filepath.Join(dir, "tls.crt.tmp")
	require.NoError(t, os.WriteFile(tmp, []byte("not a certificate"), 0o600))
	require.NoError(t, os.Rename(tmp, filepath.Join(dir, "tls.crt")))

	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "reload TLS config")
	}, 5*time.Second, 20*time.Millisecond, "the failed reload was not logged")
	requireServedCommonName(t, addr, "first")
}

func requireServedCommonName(t *testing.T, addr, want string) {
	t.Helper()
	got, err := servedCommonName(addr)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func requireEventuallyServed(t *testing.T, addr, want string) {
	t.Helper()
	require.Eventually(t, func() bool {
		got, err := servedCommonName(addr)
		return err == nil && got == want
	}, 5*time.Second, 20*time.Millisecond, "the reloader did not pick up the %q certificate", want)
}

// serveTLS completes TLS handshakes with cfg on a local listener, the way net/http does.
func serveTLS(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// net/http recovers a panic in a connection goroutine; the client sees a failed handshake.
				defer func() { _ = recover() }()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

// servedCommonName returns the certificate a client gets, asking once with SNI and once
// without it, as a client connecting by IP address does.
func servedCommonName(addr string) (string, error) {
	var names []string
	for _, serverName := range []string{"localhost", ""} {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}) //nolint:gosec // the test inspects the served certificate
		if err != nil {
			return "", fmt.Errorf("handshake with server name %q: %w", serverName, err)
		}
		names = append(names, conn.ConnectionState().PeerCertificates[0].Subject.CommonName)
		conn.Close()
	}
	if names[0] != names[1] {
		return "", fmt.Errorf("a client with SNI got %q, a client without SNI got %q", names[0], names[1])
	}
	return names[0], nil
}

func writeTestKeyPair(t *testing.T, dir, commonName string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
