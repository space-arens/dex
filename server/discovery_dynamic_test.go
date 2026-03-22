package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	api "github.com/dexidp/dex/api/v2"
	"github.com/dexidp/dex/server/signer"
	"github.com/dexidp/dex/storage"
)

type mutableDiscoverySigner struct {
	mu  sync.RWMutex
	alg jose.SignatureAlgorithm
}

func (m *mutableDiscoverySigner) Sign(context.Context, []byte) (string, error) {
	return "", nil
}

func (m *mutableDiscoverySigner) ValidationKeys(context.Context) ([]*jose.JSONWebKey, error) {
	return nil, nil
}

func (m *mutableDiscoverySigner) Algorithm(context.Context) (jose.SignatureAlgorithm, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.alg, nil
}

func (m *mutableDiscoverySigner) Start(context.Context) {}

func (m *mutableDiscoverySigner) SetAlgorithm(alg jose.SignatureAlgorithm) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alg = alg
}

func mustDiscoveryJWKPair(t *testing.T, key crypto.Signer, alg jose.SignatureAlgorithm, keyID string) (*jose.JSONWebKey, *jose.JSONWebKey) {
	t.Helper()

	return &jose.JSONWebKey{
			Key:       key,
			KeyID:     keyID,
			Algorithm: string(alg),
			Use:       "sig",
		}, &jose.JSONWebKey{
			Key:       key.Public(),
			KeyID:     keyID,
			Algorithm: string(alg),
			Use:       "sig",
		}
}

func decodeHTTPDiscovery(t *testing.T, server *Server) discovery {
	t.Helper()

	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	require.Equal(t, http.StatusOK, rr.Code)

	var res discovery
	require.NoError(t, json.NewDecoder(rr.Result().Body).Decode(&res))
	return res
}

func TestHandleDiscoveryTracksMutableSignerAlgorithm(t *testing.T) {
	sig := &mutableDiscoverySigner{alg: jose.RS256}

	httpServer, server := newTestServer(t, func(c *Config) {
		c.Signer = sig
	})
	defer httpServer.Close()

	first := decodeHTTPDiscovery(t, server)
	require.Equal(t, []string{string(jose.RS256)}, first.IDTokenAlgs)

	sig.SetAlgorithm(jose.ES256)

	second := decodeHTTPDiscovery(t, server)
	require.Equal(t, []string{string(jose.ES256), string(jose.RS256)}, second.IDTokenAlgs)
}

func TestHandleDiscoveryTracksLocalSignerAlgorithmAfterStoredKeyChange(t *testing.T) {
	start := time.Now().UTC()
	rsaPriv, rsaPub := mustDiscoveryJWKPair(t, testKey, jose.RS256, "rsa-key")

	httpServer, server := newTestServer(t, func(c *Config) {
		err := c.Storage.UpdateKeys(context.Background(), func(keys storage.Keys) (storage.Keys, error) {
			keys.SigningKey = rsaPriv
			keys.SigningKeyPub = rsaPub
			keys.NextRotation = start.Add(time.Hour)
			return keys, nil
		})
		require.NoError(t, err)

		localConfig := signer.LocalConfig{
			KeysRotationPeriod: time.Hour.String(),
			Algorithm:          string(jose.ES256),
		}
		localSig, err := localConfig.Open(context.Background(), c.Storage, time.Hour, time.Now, c.Logger)
		require.NoError(t, err)
		c.Signer = localSig
	})
	defer httpServer.Close()

	first := decodeHTTPDiscovery(t, server)
	require.Equal(t, []string{string(jose.RS256)}, first.IDTokenAlgs)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecPriv, ecPub := mustDiscoveryJWKPair(t, ecKey, jose.ES256, "ec-key")

	err = server.storage.UpdateKeys(context.Background(), func(keys storage.Keys) (storage.Keys, error) {
		keys.VerificationKeys = append(keys.VerificationKeys, storage.VerificationKey{
			PublicKey: keys.SigningKeyPub,
			Expiry:    start.Add(2 * time.Hour),
		})
		keys.SigningKey = ecPriv
		keys.SigningKeyPub = ecPub
		keys.NextRotation = start.Add(2 * time.Hour)
		return keys, nil
	})
	require.NoError(t, err)

	second := decodeHTTPDiscovery(t, server)
	require.Equal(t, []string{string(jose.ES256), string(jose.RS256)}, second.IDTokenAlgs)
}

func TestAPIGetDiscoveryTracksMutableSignerAlgorithm(t *testing.T) {
	sig := &mutableDiscoverySigner{alg: jose.RS256}

	httpServer, server := newTestServer(t, func(c *Config) {
		c.Signer = sig
	})
	defer httpServer.Close()

	apiServer := NewAPI(server.storage, slog.New(slog.DiscardHandler), "test", server)
	ctx := context.Background()

	first, err := apiServer.GetDiscovery(ctx, &api.DiscoveryReq{})
	require.NoError(t, err)
	require.Equal(t, []string{string(jose.RS256)}, first.IdTokenSigningAlgValuesSupported)

	sig.SetAlgorithm(jose.ES256)

	second, err := apiServer.GetDiscovery(ctx, &api.DiscoveryReq{})
	require.NoError(t, err)
	require.Equal(t, []string{string(jose.ES256), string(jose.RS256)}, second.IdTokenSigningAlgValuesSupported)
}
