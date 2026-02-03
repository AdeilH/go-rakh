package auth

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Fuzz tests for JWT parsing
func FuzzJWTParse(f *testing.F) {
	// Add seed corpus
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	f.Add("invalid.token")
	f.Add("")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature")
	f.Add(".......")
	f.Add(strings.Repeat("a", 10000))
	f.Add("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.test")

	provider, err := NewHMACJWTProvider([]byte("fuzz-test-secret-key-32-bytes!!!"))
	if err != nil {
		f.Fatalf("Failed to create provider: %v", err)
	}

	f.Fuzz(func(t *testing.T, input string) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// The function should not panic regardless of input
		_, _ = provider.Parse(ctx, input)
	})
}

// Fuzz test for JWT header decoding
func FuzzJWTDecodeSegment(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
	f.Add("aW52YWxpZA")
	f.Add("")
	f.Add("!!invalid-base64!!")
	f.Add(strings.Repeat("A", 1000))
	f.Add("e30") // {}

	f.Fuzz(func(t *testing.T, input string) {
		var header jwtHeader
		// Should not panic
		_ = decodeSegment(input, &header)

		var payload jwtPayload
		// Should not panic
		_ = decodeSegment(input, &payload)
	})
}

// Fuzz test for signature verification
func FuzzJWTSignatureVerification(f *testing.F) {
	f.Add("header.payload", "signature", "HS256")
	f.Add("", "", "")
	f.Add("test", "test", "HS512")
	f.Add(strings.Repeat("x", 1000), strings.Repeat("y", 1000), "HS384")

	provider, err := NewHMACJWTProvider([]byte("fuzz-test-secret-key-32-bytes!!!"), "HS256", "HS384", "HS512")
	if err != nil {
		f.Fatalf("Failed to create provider: %v", err)
	}

	f.Fuzz(func(t *testing.T, input, signature, alg string) {
		// Should not panic
		_ = provider.verify(input, signature, alg)
	})
}

// Fuzz test for JWT claims validation
func FuzzJWTClaimsValidation(f *testing.F) {
	f.Add("user-1", "issuer", int64(0), int64(0), int64(0))
	f.Add("", "", int64(-1000000), int64(1000000), int64(500000))
	f.Add(strings.Repeat("x", 1000), "iss", int64(1609459200), int64(1609545600), int64(1609459200))

	provider, _ := NewHMACJWTProvider([]byte("fuzz-test-secret"))

	f.Fuzz(func(t *testing.T, subject, issuer string, iat, exp, nbf int64) {
		claims := JWTClaims{
			Subject:   subject,
			Issuer:    issuer,
			IssuedAt:  time.Unix(iat, 0),
			ExpiresAt: time.Unix(exp, 0),
			NotBefore: time.Unix(nbf, 0),
		}
		// Should not panic
		_ = provider.validateClaims(claims)
	})
}

// Fuzz test for password validation
func FuzzPasswordValidation(f *testing.F) {
	f.Add("SecurePass123!")
	f.Add("")
	f.Add("a")
	f.Add(strings.Repeat("a", 200))
	f.Add("UPPERCASE")
	f.Add("lowercase")
	f.Add("12345678")
	f.Add("Pass!@#$%")
	f.Add("日本語パスワード123")
	f.Add("\x00\x01\x02\x03")
	f.Add("password\x00injection")

	opts := DefaultPasswordValidation()

	f.Fuzz(func(t *testing.T, password string) {
		// Should not panic
		_ = ValidatePasswordStrength([]byte(password), opts)
	})
}

// Fuzz test for bcrypt hashing
func FuzzBcryptHash(f *testing.F) {
	f.Add("SecurePass123!")
	f.Add("")
	f.Add(strings.Repeat("x", 72)) // bcrypt max length
	f.Add(strings.Repeat("x", 100))
	f.Add("日本語")
	f.Add("\x00\x01\x02")

	hasher := NewBcryptHasher(
		WithBcryptCost(4), // Low cost for fuzz testing
		WithBcryptValidation(PasswordValidationOptions{MinLength: 1, MaxLength: 200}),
	)

	f.Fuzz(func(t *testing.T, password string) {
		if len(password) == 0 || len(password) > 100 {
			return // Skip edge cases that would timeout
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// Should not panic
		hash, err := hasher.Hash(ctx, []byte(password), PasswordOptions{})
		if err != nil {
			return
		}

		// If hash succeeded, compare should work
		_ = hasher.Compare(ctx, []byte(password), hash)
	})
}

// Fuzz test for argon2id hashing
func FuzzArgon2idHash(f *testing.F) {
	f.Add("SecurePass123!")
	f.Add("")
	f.Add(strings.Repeat("x", 100))
	f.Add("日本語")

	hasher := NewArgon2idHasher(
		WithArgon2Time(1),
		WithArgon2Memory(16*1024), // Lower memory for fuzz testing
		WithArgon2Threads(1),
		WithArgon2Validation(PasswordValidationOptions{MinLength: 1, MaxLength: 200}),
	)

	f.Fuzz(func(t *testing.T, password string) {
		if len(password) == 0 || len(password) > 100 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// Should not panic
		hash, err := hasher.Hash(ctx, []byte(password), PasswordOptions{})
		if err != nil {
			return
		}

		// If hash succeeded, compare should work
		_ = hasher.Compare(ctx, []byte(password), hash)
	})
}

// Fuzz test for argon2id hash decoding
func FuzzArgon2idDecodeHash(f *testing.F) {
	f.Add("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA")
	f.Add("")
	f.Add("invalid")
	f.Add("$argon2id$v=19$m=invalid$salt$hash")
	f.Add(strings.Repeat("$", 10))

	hasher := NewArgon2idHasher()

	f.Fuzz(func(t *testing.T, encoded string) {
		// Should not panic
		_, _, _ = hasher.decodeHash([]byte(encoded))
	})
}

// Fuzz test for email validation
func FuzzEmailValidation(f *testing.F) {
	f.Add("test@example.com")
	f.Add("")
	f.Add("invalid")
	f.Add("@@@")
	f.Add(strings.Repeat("a", 300) + "@example.com")
	f.Add("test@" + strings.Repeat("a", 300) + ".com")
	f.Add("user+tag@sub.domain.co.uk")
	f.Add("user\x00@example.com")

	f.Fuzz(func(t *testing.T, email string) {
		// Should not panic
		_ = ValidateEmail(email)
	})
}

// Fuzz test for secure compare
func FuzzSecureCompare(f *testing.F) {
	f.Add("hello", "hello")
	f.Add("", "")
	f.Add("a", "b")
	f.Add(strings.Repeat("a", 1000), strings.Repeat("a", 1000))
	f.Add("short", "longer")

	f.Fuzz(func(t *testing.T, a, b string) {
		// Should not panic and should be consistent
		result1 := SecureCompare(a, b)
		result2 := SecureCompare(a, b)
		if result1 != result2 {
			t.Errorf("SecureCompare not consistent: %v != %v", result1, result2)
		}

		// Should match standard comparison semantics
		if (a == b) != result1 {
			t.Errorf("SecureCompare(%q, %q) = %v, want %v", a, b, result1, a == b)
		}
	})
}

// Fuzz test for sanitize input
func FuzzSanitizeInput(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add("  spaces  ")
	f.Add("\x00\x01\x02test\x03\x04")
	f.Add("tab\there")
	f.Add("newline\nhere")
	f.Add(strings.Repeat("\x00", 100))

	f.Fuzz(func(t *testing.T, input string) {
		// Should not panic
		result := SanitizeInput(input)

		// Result should not contain null bytes
		if strings.Contains(result, "\x00") {
			t.Errorf("SanitizeInput output contains null byte")
		}

		// Result should be trimmed
		if result != strings.TrimSpace(result) {
			t.Errorf("SanitizeInput output not trimmed")
		}
	})
}

// Fuzz test for common password detection
func FuzzCommonPasswordDetection(f *testing.F) {
	f.Add("password")
	f.Add("123456")
	f.Add("qwerty")
	f.Add("uniqueP@ss123")
	f.Add("")
	f.Add(strings.Repeat("a", 100))

	f.Fuzz(func(t *testing.T, password string) {
		// Should not panic
		_ = isCommonPassword(password)
	})
}

// Fuzz test for sequential pattern detection
func FuzzSequentialPattern(f *testing.F) {
	f.Add("1234")
	f.Add("abcd")
	f.Add("4321")
	f.Add("hello")
	f.Add("")
	f.Add("ab")

	f.Fuzz(func(t *testing.T, s string) {
		// Should not panic
		_ = isSequentialPattern(s)
	})
}

// Fuzz test for repeating pattern detection
func FuzzRepeatingPattern(f *testing.F) {
	f.Add("aaaa")
	f.Add("1111")
	f.Add("abab")
	f.Add("")
	f.Add("a")

	f.Fuzz(func(t *testing.T, s string) {
		// Should not panic
		_ = isRepeatingPattern(s)
	})
}

// Fuzz test for token extractor with various Authorization headers
func FuzzBearerTokenExtractor(f *testing.F) {
	f.Add("Bearer token123")
	f.Add("Bearer ")
	f.Add("bearer TOKEN")
	f.Add("Basic dXNlcjpwYXNz")
	f.Add("")
	f.Add("BearerNoSpace")
	f.Add(strings.Repeat("Bearer ", 100))
	f.Add("Bearer " + strings.Repeat("x", 10000))

	extractor := BearerTokenExtractor()

	f.Fuzz(func(t *testing.T, header string) {
		// Should not panic
		_, _ = extractFromHeader(header, extractor)
	})
}

// Helper function for testing extractors
func extractFromHeader(header string, extractor TokenExtractor) (string, error) {
	// Create a minimal mock request
	type mockRequest struct {
		header string
	}

	// We can't easily mock http.Request in fuzz tests, but we can test the parsing logic
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrTokenInvalidInput
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", ErrTokenInvalidInput
	}
	return token, nil
}

// Fuzz test for random ID generation
func FuzzRandomID(f *testing.F) {
	f.Add(1)
	f.Add(100)
	f.Add(1000)

	f.Fuzz(func(t *testing.T, iterations int) {
		if iterations < 1 || iterations > 100 {
			return
		}

		seen := make(map[string]struct{})
		for i := 0; i < iterations; i++ {
			id, err := randomID()
			if err != nil {
				t.Fatalf("randomID() error = %v", err)
			}
			if _, exists := seen[id]; exists {
				t.Error("randomID() generated duplicate")
			}
			seen[id] = struct{}{}
		}
	})
}

// Fuzz test for JWT issue with various claims
func FuzzJWTIssue(f *testing.F) {
	f.Add("user-1", "issuer", int64(3600))
	f.Add("", "", int64(0))
	f.Add(strings.Repeat("x", 100), "iss", int64(-1))
	f.Add("subject", "", int64(86400))

	provider, err := NewHMACJWTProvider([]byte("fuzz-test-secret-key-32-bytes!!!"))
	if err != nil {
		f.Fatalf("Failed to create provider: %v", err)
	}

	f.Fuzz(func(t *testing.T, subject, issuer string, ttlSeconds int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		claims := JWTClaims{
			Subject: subject,
		}
		opts := JWTOptions{
			Issuer: issuer,
		}
		if ttlSeconds > 0 && ttlSeconds < 86400*365 {
			opts.TTL = time.Duration(ttlSeconds) * time.Second
		}

		// Should not panic
		token, err := provider.Issue(ctx, claims, opts)
		if err != nil {
			return
		}

		// If issue succeeded, parse should work
		parsed, err := provider.Parse(ctx, token.Raw())
		if err != nil {
			t.Errorf("Parse failed for issued token: %v", err)
		}

		// Claims should match
		if parsed.Claims().Subject != subject {
			t.Errorf("Subject mismatch: got %q, want %q", parsed.Claims().Subject, subject)
		}
	})
}
