package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Tests for security features

func TestNewSecureHMACJWTProvider(t *testing.T) {
	t.Run("valid secret for HS256", func(t *testing.T) {
		secret := make([]byte, 32)
		for i := range secret {
			secret[i] = byte(i)
		}
		provider, err := NewSecureHMACJWTProvider(secret, "HS256")
		if err != nil {
			t.Fatalf("NewSecureHMACJWTProvider() error = %v", err)
		}
		if provider == nil {
			t.Fatal("provider should not be nil")
		}
	})

	t.Run("secret too short for HS256", func(t *testing.T) {
		secret := make([]byte, 16) // Too short
		_, err := NewSecureHMACJWTProvider(secret, "HS256")
		if !errors.Is(err, ErrJWTWeakSigningKey) {
			t.Errorf("error = %v, want ErrJWTWeakSigningKey", err)
		}
	})

	t.Run("valid secret for HS384", func(t *testing.T) {
		secret := make([]byte, 48)
		for i := range secret {
			secret[i] = byte(i)
		}
		provider, err := NewSecureHMACJWTProvider(secret, "HS384")
		if err != nil {
			t.Fatalf("NewSecureHMACJWTProvider() error = %v", err)
		}
		if provider == nil {
			t.Fatal("provider should not be nil")
		}
	})

	t.Run("secret too short for HS384", func(t *testing.T) {
		secret := make([]byte, 32) // Too short for HS384
		_, err := NewSecureHMACJWTProvider(secret, "HS384")
		if !errors.Is(err, ErrJWTWeakSigningKey) {
			t.Errorf("error = %v, want ErrJWTWeakSigningKey", err)
		}
	})

	t.Run("valid secret for HS512", func(t *testing.T) {
		secret := make([]byte, 64)
		for i := range secret {
			secret[i] = byte(i)
		}
		provider, err := NewSecureHMACJWTProvider(secret, "HS512")
		if err != nil {
			t.Fatalf("NewSecureHMACJWTProvider() error = %v", err)
		}
		if provider == nil {
			t.Fatal("provider should not be nil")
		}
	})

	t.Run("secret too short for HS512", func(t *testing.T) {
		secret := make([]byte, 48) // Too short for HS512
		_, err := NewSecureHMACJWTProvider(secret, "HS512")
		if !errors.Is(err, ErrJWTWeakSigningKey) {
			t.Errorf("error = %v, want ErrJWTWeakSigningKey", err)
		}
	})

	t.Run("multiple algorithms use max requirement", func(t *testing.T) {
		secret := make([]byte, 48) // Enough for HS256/384 but not HS512
		_, err := NewSecureHMACJWTProvider(secret, "HS256", "HS384", "HS512")
		if !errors.Is(err, ErrJWTWeakSigningKey) {
			t.Errorf("error = %v, want ErrJWTWeakSigningKey", err)
		}

		secret = make([]byte, 64)
		for i := range secret {
			secret[i] = byte(i)
		}
		provider, err := NewSecureHMACJWTProvider(secret, "HS256", "HS384", "HS512")
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if provider == nil {
			t.Fatal("provider should not be nil")
		}
	})

	t.Run("defaults to HS256", func(t *testing.T) {
		secret := make([]byte, 32)
		for i := range secret {
			secret[i] = byte(i)
		}
		provider, err := NewSecureHMACJWTProvider(secret)
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if provider.defaultAlg != "HS256" {
			t.Errorf("defaultAlg = %s, want HS256", provider.defaultAlg)
		}
	})
}

func TestJWTIssuerValidation(t *testing.T) {
	ctx := context.Background()
	secret := []byte("test-secret-key-32-bytes-long!!!")
	provider, _ := NewHMACJWTProvider(secret)
	provider.SetRequiredIssuer("trusted-issuer")

	t.Run("valid issuer", func(t *testing.T) {
		claims := JWTClaims{Subject: "user"}
		opts := JWTOptions{Issuer: "trusted-issuer", TTL: time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		_, err = provider.Parse(ctx, token.Raw())
		if err != nil {
			t.Errorf("Parse() error = %v", err)
		}
	})

	t.Run("invalid issuer", func(t *testing.T) {
		claims := JWTClaims{Subject: "user"}
		opts := JWTOptions{Issuer: "untrusted-issuer", TTL: time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		_, err = provider.Parse(ctx, token.Raw())
		if !errors.Is(err, ErrJWTInvalidIssuer) {
			t.Errorf("Parse() error = %v, want ErrJWTInvalidIssuer", err)
		}
	})

	t.Run("missing issuer", func(t *testing.T) {
		claims := JWTClaims{Subject: "user"}
		opts := JWTOptions{TTL: time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		_, err = provider.Parse(ctx, token.Raw())
		if !errors.Is(err, ErrJWTInvalidIssuer) {
			t.Errorf("Parse() error = %v, want ErrJWTInvalidIssuer", err)
		}
	})
}

func TestJWTAudienceValidation(t *testing.T) {
	ctx := context.Background()
	secret := []byte("test-secret-key-32-bytes-long!!!")
	provider, _ := NewHMACJWTProvider(secret)
	provider.SetRequiredAudience("service-a", "service-b")

	t.Run("valid audience single match", func(t *testing.T) {
		claims := JWTClaims{Subject: "user", Audience: []string{"service-a"}}
		opts := JWTOptions{TTL: time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		_, err = provider.Parse(ctx, token.Raw())
		if err != nil {
			t.Errorf("Parse() error = %v", err)
		}
	})

	t.Run("valid audience multiple match", func(t *testing.T) {
		claims := JWTClaims{Subject: "user", Audience: []string{"service-a", "service-c"}}
		opts := JWTOptions{TTL: time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		_, err = provider.Parse(ctx, token.Raw())
		if err != nil {
			t.Errorf("Parse() error = %v", err)
		}
	})

	t.Run("invalid audience", func(t *testing.T) {
		claims := JWTClaims{Subject: "user", Audience: []string{"service-x"}}
		opts := JWTOptions{TTL: time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		_, err = provider.Parse(ctx, token.Raw())
		if !errors.Is(err, ErrJWTInvalidAudience) {
			t.Errorf("Parse() error = %v, want ErrJWTInvalidAudience", err)
		}
	})

	t.Run("missing audience", func(t *testing.T) {
		claims := JWTClaims{Subject: "user"}
		opts := JWTOptions{TTL: time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		_, err = provider.Parse(ctx, token.Raw())
		if !errors.Is(err, ErrJWTInvalidAudience) {
			t.Errorf("Parse() error = %v, want ErrJWTInvalidAudience", err)
		}
	})
}

func TestHasAudienceMatch(t *testing.T) {
	tests := []struct {
		name        string
		tokenAud    []string
		requiredAud []string
		want        bool
	}{
		{"both empty", nil, nil, false},
		{"token empty", nil, []string{"a"}, false},
		{"required empty", []string{"a"}, nil, false},
		{"single match", []string{"a"}, []string{"a"}, true},
		{"no match", []string{"a"}, []string{"b"}, false},
		{"partial match", []string{"a", "b"}, []string{"b", "c"}, true},
		{"multiple token single required", []string{"a", "b", "c"}, []string{"b"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasAudienceMatch(tt.tokenAud, tt.requiredAud); got != tt.want {
				t.Errorf("hasAudienceMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWTClaimsExpiration(t *testing.T) {
	ctx := context.Background()
	secret := []byte("test-secret-key-32-bytes-long!!!")
	provider, _ := NewHMACJWTProvider(secret)
	provider.SetLeeway(0) // No leeway for precise testing

	now := time.Now()
	provider.SetNowFunc(func() time.Time { return now })

	t.Run("valid token", func(t *testing.T) {
		claims := JWTClaims{Subject: "user"}
		opts := JWTOptions{TTL: time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		_, err = provider.Parse(ctx, token.Raw())
		if err != nil {
			t.Errorf("Parse() error = %v", err)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		claims := JWTClaims{Subject: "user"}
		opts := JWTOptions{TTL: time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		// Move time forward
		provider.SetNowFunc(func() time.Time { return now.Add(2 * time.Hour) })

		_, err = provider.Parse(ctx, token.Raw())
		if !errors.Is(err, ErrJWTExpired) {
			t.Errorf("Parse() error = %v, want ErrJWTExpired", err)
		}
	})

	t.Run("not yet valid token", func(t *testing.T) {
		provider.SetNowFunc(func() time.Time { return now })

		claims := JWTClaims{
			Subject:   "user",
			NotBefore: now.Add(time.Hour),
		}
		opts := JWTOptions{TTL: 2 * time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		_, err = provider.Parse(ctx, token.Raw())
		if !errors.Is(err, ErrJWTNotYetValid) {
			t.Errorf("Parse() error = %v, want ErrJWTNotYetValid", err)
		}
	})

	t.Run("leeway allows slightly expired", func(t *testing.T) {
		provider.SetNowFunc(func() time.Time { return now })
		provider.SetLeeway(5 * time.Minute)

		claims := JWTClaims{Subject: "user"}
		opts := JWTOptions{TTL: time.Hour}

		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		// Move time forward by slightly more than TTL but within leeway
		provider.SetNowFunc(func() time.Time { return now.Add(time.Hour + 3*time.Minute) })

		_, err = provider.Parse(ctx, token.Raw())
		if err != nil {
			t.Errorf("Parse() should succeed within leeway, got error = %v", err)
		}
	})
}

func TestJWTTokenManipulation(t *testing.T) {
	ctx := context.Background()
	secret := []byte("test-secret-key-32-bytes-long!!!")
	provider, _ := NewHMACJWTProvider(secret)

	claims := JWTClaims{Subject: "user"}
	opts := JWTOptions{TTL: time.Hour}

	token, _ := provider.Issue(ctx, claims, opts)
	raw := token.Raw()

	t.Run("modified header", func(t *testing.T) {
		parts := strings.Split(raw, ".")
		modified := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + parts[1] + "." + parts[2]
		_, err := provider.Parse(ctx, modified)
		if err == nil {
			t.Error("Parse() should fail for modified header")
		}
	})

	t.Run("modified payload", func(t *testing.T) {
		parts := strings.Split(raw, ".")
		modified := parts[0] + ".eyJzdWIiOiJhZG1pbiJ9." + parts[2]
		_, err := provider.Parse(ctx, modified)
		if !errors.Is(err, ErrJWTInvalidSignature) {
			t.Errorf("Parse() error = %v, want ErrJWTInvalidSignature", err)
		}
	})

	t.Run("modified signature", func(t *testing.T) {
		parts := strings.Split(raw, ".")
		modified := parts[0] + "." + parts[1] + ".tampered"
		_, err := provider.Parse(ctx, modified)
		if !errors.Is(err, ErrJWTInvalidSignature) {
			t.Errorf("Parse() error = %v, want ErrJWTInvalidSignature", err)
		}
	})

	t.Run("missing signature", func(t *testing.T) {
		parts := strings.Split(raw, ".")
		modified := parts[0] + "." + parts[1]
		_, err := provider.Parse(ctx, modified)
		if !errors.Is(err, ErrJWTInvalidFormat) {
			t.Errorf("Parse() error = %v, want ErrJWTInvalidFormat", err)
		}
	})

	t.Run("extra parts", func(t *testing.T) {
		modified := raw + ".extra"
		_, err := provider.Parse(ctx, modified)
		if !errors.Is(err, ErrJWTInvalidFormat) {
			t.Errorf("Parse() error = %v, want ErrJWTInvalidFormat", err)
		}
	})
}

func TestJWTAlgorithmConfusion(t *testing.T) {
	ctx := context.Background()

	t.Run("reject unsupported algorithm", func(t *testing.T) {
		secret := []byte("test-secret-key-32-bytes-long!!!")
		provider, _ := NewHMACJWTProvider(secret, "HS256")

		// Create token with HS512 (not allowed)
		_, err := provider.Issue(ctx, JWTClaims{Subject: "user"}, JWTOptions{
			TTL:       time.Hour,
			Algorithm: "HS512",
		})
		if !errors.Is(err, ErrJWTUnsupportedAlgo) {
			t.Errorf("Issue() error = %v, want ErrJWTUnsupportedAlgo", err)
		}
	})

	t.Run("cross-algorithm token rejected", func(t *testing.T) {
		secret := []byte("test-secret-key-64-bytes-long-for-hs512-algorithm-requirement!!!")
		
		provider256, _ := NewHMACJWTProvider(secret, "HS256")
		provider512, _ := NewHMACJWTProvider(secret, "HS512")

		token, _ := provider512.Issue(ctx, JWTClaims{Subject: "user"}, JWTOptions{TTL: time.Hour})

		// Try to parse HS512 token with HS256-only provider
		_, err := provider256.Parse(ctx, token.Raw())
		if !errors.Is(err, ErrJWTUnsupportedAlgo) {
			t.Errorf("Parse() error = %v, want ErrJWTUnsupportedAlgo", err)
		}
	})
}

func TestJWTRevocation(t *testing.T) {
	ctx := context.Background()
	secret := []byte("test-secret-key-32-bytes-long!!!")
	provider, _ := NewHMACJWTProvider(secret)

	t.Run("revoked token cannot be parsed", func(t *testing.T) {
		token, _ := provider.Issue(ctx, JWTClaims{Subject: "user"}, JWTOptions{TTL: time.Hour})

		// Verify token works
		_, err := provider.Parse(ctx, token.Raw())
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}

		// Revoke
		err = provider.Revoke(ctx, token.Claims().ID)
		if err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}

		// Verify token is rejected
		_, err = provider.Parse(ctx, token.Raw())
		if !errors.Is(err, ErrJWTRevoked) {
			t.Errorf("Parse() error = %v, want ErrJWTRevoked", err)
		}
	})

	t.Run("revoke empty token ID", func(t *testing.T) {
		err := provider.Revoke(ctx, "")
		if err == nil {
			t.Error("Revoke() should fail for empty token ID")
		}
	})
}

func TestJWTNegativeTTL(t *testing.T) {
	ctx := context.Background()
	secret := []byte("test-secret-key-32-bytes-long!!!")
	provider, _ := NewHMACJWTProvider(secret)

	_, err := provider.Issue(ctx, JWTClaims{Subject: "user"}, JWTOptions{TTL: -time.Hour})
	if !errors.Is(err, ErrJWTInvalidClaims) {
		t.Errorf("Issue() error = %v, want ErrJWTInvalidClaims", err)
	}
}

func TestJWTExpiresBeforeIssued(t *testing.T) {
	ctx := context.Background()
	secret := []byte("test-secret-key-32-bytes-long!!!")
	provider, _ := NewHMACJWTProvider(secret)

	now := time.Now()
	claims := JWTClaims{
		Subject:   "user",
		IssuedAt:  now,
		ExpiresAt: now.Add(-time.Hour), // Before IssuedAt
	}

	_, err := provider.Issue(ctx, claims, JWTOptions{})
	if !errors.Is(err, ErrJWTInvalidClaims) {
		t.Errorf("Issue() error = %v, want ErrJWTInvalidClaims", err)
	}
}

func TestContextError(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!!")
	provider, _ := NewHMACJWTProvider(secret)

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := provider.Issue(ctx, JWTClaims{Subject: "user"}, JWTOptions{TTL: time.Hour})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Issue() error = %v, want context.Canceled", err)
		}
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()

		time.Sleep(time.Millisecond)
		_, err := provider.Issue(ctx, JWTClaims{Subject: "user"}, JWTOptions{TTL: time.Hour})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Issue() error = %v, want context.DeadlineExceeded", err)
		}
	})

	t.Run("nil context is ok", func(t *testing.T) {
		if err := contextError(nil); err != nil {
			t.Errorf("contextError(nil) = %v, want nil", err)
		}
	})
}

func TestCloneHelpers(t *testing.T) {
	t.Run("cloneStrings nil", func(t *testing.T) {
		if cloneStrings(nil) != nil {
			t.Error("cloneStrings(nil) should return nil")
		}
	})

	t.Run("cloneStrings empty", func(t *testing.T) {
		if cloneStrings([]string{}) != nil {
			t.Error("cloneStrings([]) should return nil")
		}
	})

	t.Run("cloneStrings independent", func(t *testing.T) {
		orig := []string{"a", "b"}
		clone := cloneStrings(orig)
		clone[0] = "x"
		if orig[0] == "x" {
			t.Error("clone modified original")
		}
	})

	t.Run("cloneMetadata nil", func(t *testing.T) {
		if cloneMetadata(nil) != nil {
			t.Error("cloneMetadata(nil) should return nil")
		}
	})

	t.Run("cloneMetadata empty", func(t *testing.T) {
		if cloneMetadata(map[string]any{}) != nil {
			t.Error("cloneMetadata({}) should return nil")
		}
	})

	t.Run("cloneMetadata independent", func(t *testing.T) {
		orig := map[string]any{"key": "value"}
		clone := cloneMetadata(orig)
		clone["key"] = "modified"
		if orig["key"] == "modified" {
			t.Error("clone modified original")
		}
	})
}

func TestRandomID(t *testing.T) {
	t.Run("generates unique IDs", func(t *testing.T) {
		seen := make(map[string]struct{})
		for i := 0; i < 1000; i++ {
			id, err := randomID()
			if err != nil {
				t.Fatalf("randomID() error = %v", err)
			}
			if _, exists := seen[id]; exists {
				t.Errorf("duplicate ID generated: %s", id)
			}
			seen[id] = struct{}{}
		}
	})

	t.Run("ID has expected length", func(t *testing.T) {
		id, err := randomID()
		if err != nil {
			t.Fatalf("randomID() error = %v", err)
		}
		// 32 bytes = 43 characters in base64 (no padding)
		if len(id) != 43 {
			t.Errorf("ID length = %d, want 43", len(id))
		}
	})
}
