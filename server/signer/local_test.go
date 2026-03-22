package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func newTestLocalSigner(t *testing.T, config LocalConfig, s storage.Storage, now func() time.Time) *localSigner {
	t.Helper()

	logger := slog.New(slog.DiscardHandler)
	if s == nil {
		s = memory.New(logger)
	}
	if config.KeysRotationPeriod == "" {
		config.KeysRotationPeriod = time.Hour.String()
	}
	if now == nil {
		now = time.Now
	}

	sig, err := config.Open(context.Background(), s, time.Hour, now, logger)
	require.NoError(t, err)

	ls, ok := sig.(*localSigner)
	require.True(t, ok)
	return ls
}

func newTestJWKPair(t *testing.T, alg jose.SignatureAlgorithm) (*jose.JSONWebKey, *jose.JSONWebKey) {
	t.Helper()

	switch alg {
	case jose.RS256:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		priv, pub, err := newJWKPair(key, alg)
		require.NoError(t, err)
		return priv, pub
	case jose.ES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		priv, pub, err := newJWKPair(key, alg)
		require.NoError(t, err)
		return priv, pub
	default:
		t.Fatalf("unsupported test algorithm %s", alg)
		return nil, nil
	}
}

func requireVerifiedByAnyKey(t *testing.T, token string, alg jose.SignatureAlgorithm, keys []*jose.JSONWebKey, wantPayload []byte) {
	t.Helper()

	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{alg})
	require.NoError(t, err)

	for _, key := range keys {
		payload, err := jws.Verify(key)
		if err == nil {
			require.Equal(t, wantPayload, payload)
			return
		}
	}

	t.Fatalf("token did not verify with any key for algorithm %s", alg)
}

func TestLocalSignerAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		cfg  LocalConfig
		want jose.SignatureAlgorithm
	}{
		{
			name: "default RS256 before first rotation",
			cfg:  LocalConfig{KeysRotationPeriod: time.Hour.String()},
			want: jose.RS256,
		},
		{
			name: "ES256 before first rotation",
			cfg:  LocalConfig{KeysRotationPeriod: time.Hour.String(), Algorithm: string(jose.ES256)},
			want: jose.ES256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := newTestLocalSigner(t, tt.cfg, nil, nil)

			alg, err := ls.Algorithm(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, alg)
		})
	}
}

func TestLocalSignerSignAndValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  LocalConfig
		want jose.SignatureAlgorithm
	}{
		{
			name: "RS256",
			cfg:  LocalConfig{KeysRotationPeriod: time.Hour.String()},
			want: jose.RS256,
		},
		{
			name: "ES256",
			cfg:  LocalConfig{KeysRotationPeriod: time.Hour.String(), Algorithm: string(jose.ES256)},
			want: jose.ES256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := newTestLocalSigner(t, tt.cfg, nil, nil)
			ctx := context.Background()

			require.NoError(t, ls.rotator.rotate())

			payload := []byte(`{"sub":"test-user"}`)
			signed, err := ls.Sign(ctx, payload)
			require.NoError(t, err)
			assert.NotEmpty(t, signed)

			keys, err := ls.ValidationKeys(ctx)
			require.NoError(t, err)
			require.Len(t, keys, 1)
			assert.Equal(t, string(tt.want), keys[0].Algorithm)

			alg, err := ls.Algorithm(ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.want, alg)

			requireVerifiedByAnyKey(t, signed, tt.want, keys, payload)
		})
	}
}

func TestLocalSignerAppliesConfiguredAlgorithmOnNextRotation(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	s := memory.New(logger)

	start := time.Now().UTC()
	current := start

	rsaPriv, rsaPub := newTestJWKPair(t, jose.RS256)
	err := s.UpdateKeys(context.Background(), func(keys storage.Keys) (storage.Keys, error) {
		keys.SigningKey = rsaPriv
		keys.SigningKeyPub = rsaPub
		keys.NextRotation = start.Add(time.Hour)
		return keys, nil
	})
	require.NoError(t, err)

	ls := newTestLocalSigner(
		t,
		LocalConfig{KeysRotationPeriod: time.Hour.String(), Algorithm: string(jose.ES256)},
		s,
		func() time.Time { return current },
	)
	ctx := context.Background()

	beforeAlg, err := ls.Algorithm(ctx)
	require.NoError(t, err)
	assert.Equal(t, jose.RS256, beforeAlg)

	beforePayload := []byte(`{"sub":"before-rotation"}`)
	beforeToken, err := ls.Sign(ctx, beforePayload)
	require.NoError(t, err)

	current = start.Add(30 * time.Minute)
	require.NoError(t, ls.rotator.rotate())

	unchangedAlg, err := ls.Algorithm(ctx)
	require.NoError(t, err)
	assert.Equal(t, jose.RS256, unchangedAlg)

	current = start.Add(2 * time.Hour)
	require.NoError(t, ls.rotator.rotate())

	afterAlg, err := ls.Algorithm(ctx)
	require.NoError(t, err)
	assert.Equal(t, jose.ES256, afterAlg)

	afterPayload := []byte(`{"sub":"after-rotation"}`)
	afterToken, err := ls.Sign(ctx, afterPayload)
	require.NoError(t, err)

	keys, err := ls.ValidationKeys(ctx)
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, string(jose.ES256), keys[0].Algorithm)
	assert.Equal(t, string(jose.RS256), keys[1].Algorithm)

	requireVerifiedByAnyKey(t, beforeToken, jose.RS256, keys, beforePayload)
	requireVerifiedByAnyKey(t, afterToken, jose.ES256, keys, afterPayload)
}
