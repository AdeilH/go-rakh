package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		opts     PasswordValidationOptions
		wantErr  error
	}{
		{
			name:     "valid password with defaults",
			password: "SecurePass123",
			opts:     DefaultPasswordValidation(),
			wantErr:  nil,
		},
		{
			name:     "empty password",
			password: "",
			opts:     DefaultPasswordValidation(),
			wantErr:  ErrPasswordTooShort,
		},
		{
			name:     "too short",
			password: "Abc1234",
			opts:     DefaultPasswordValidation(),
			wantErr:  ErrPasswordTooShort,
		},
		{
			name:     "too long",
			password: strings.Repeat("Aa1", 50),
			opts:     PasswordValidationOptions{MaxLength: 10},
			wantErr:  ErrPasswordTooLong,
		},
		{
			name:     "missing uppercase",
			password: "lowercase123",
			opts:     DefaultPasswordValidation(),
			wantErr:  ErrPasswordNoUppercase,
		},
		{
			name:     "missing lowercase",
			password: "UPPERCASE123",
			opts:     DefaultPasswordValidation(),
			wantErr:  ErrPasswordNoLowercase,
		},
		{
			name:     "missing digit",
			password: "NoDigitsHere",
			opts:     DefaultPasswordValidation(),
			wantErr:  ErrPasswordNoDigit,
		},
		{
			name:     "missing special when required",
			password: "NoSpecial123",
			opts:     StrictPasswordValidation(),
			wantErr:  ErrPasswordNoSpecial,
		},
		{
			name:     "valid with special character",
			password: "Secure!Pass123",
			opts:     StrictPasswordValidation(),
			wantErr:  nil,
		},
		{
			name:     "common password",
			password: "Password123",
			opts:     DefaultPasswordValidation(),
			wantErr:  ErrPasswordCommon,
		},
		{
			name:     "sequential pattern",
			password: "Abcdefgh1",
			opts:     DefaultPasswordValidation(),
			wantErr:  ErrPasswordCommon,
		},
		{
			name:     "repeating pattern",
			password: "Aaaaaaa1b",
			opts:     DefaultPasswordValidation(),
			wantErr:  nil, // Not repeating enough
		},
		{
			name:     "unicode password valid",
			password: "Sécure123日本語",
			opts:     DefaultPasswordValidation(),
			wantErr:  nil,
		},
		{
			name:     "minimum length edge case",
			password: "Abc12345",
			opts:     DefaultPasswordValidation(),
			wantErr:  nil,
		},
		{
			name:     "no validation required",
			password: "simple",
			opts: PasswordValidationOptions{
				MinLength:        1,
				MaxLength:        100,
				RequireUppercase: false,
				RequireLowercase: false,
				RequireDigit:     false,
				RequireSpecial:   false,
				CheckCommon:      false,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength([]byte(tt.password), tt.opts)
			if tt.wantErr == nil && err != nil {
				t.Errorf("ValidatePasswordStrength() unexpected error = %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidatePasswordStrength() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestBcryptHasher_Hash(t *testing.T) {
	ctx := context.Background()
	hasher := NewBcryptHasher(
		WithBcryptCost(4), // Lower cost for faster tests
		WithBcryptValidation(PasswordValidationOptions{
			MinLength:        8,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireDigit:     true,
			CheckCommon:      true,
		}),
	)

	t.Run("valid password", func(t *testing.T) {
		hash, err := hasher.Hash(ctx, []byte("SecurePass123"), PasswordOptions{})
		if err != nil {
			t.Fatalf("Hash() error = %v", err)
		}
		if hash.Algorithm != AlgorithmBcrypt {
			t.Errorf("Algorithm = %s, want %s", hash.Algorithm, AlgorithmBcrypt)
		}
		if len(hash.Value) == 0 {
			t.Error("Hash value is empty")
		}
		if len(hash.Salt) == 0 {
			t.Error("Salt is empty")
		}
		if hash.CreatedAt.IsZero() {
			t.Error("CreatedAt is zero")
		}
	})

	t.Run("invalid password rejected", func(t *testing.T) {
		_, err := hasher.Hash(ctx, []byte("weak"), PasswordOptions{})
		if err == nil {
			t.Error("Hash() should reject weak password")
		}
	})

	t.Run("with pepper", func(t *testing.T) {
		pepperedHasher := NewBcryptHasher(
			WithBcryptCost(4),
			WithBcryptPepper([]byte("server-secret")),
			WithBcryptValidation(PasswordValidationOptions{MinLength: 1}),
		)
		hash, err := pepperedHasher.Hash(ctx, []byte("SecurePass123"), PasswordOptions{})
		if err != nil {
			t.Fatalf("Hash() with pepper error = %v", err)
		}
		if len(hash.Value) == 0 {
			t.Error("Hash value is empty")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := hasher.Hash(cancelledCtx, []byte("SecurePass123"), PasswordOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Hash() error = %v, want context.Canceled", err)
		}
	})
}

func TestBcryptHasher_Compare(t *testing.T) {
	ctx := context.Background()
	hasher := NewBcryptHasher(
		WithBcryptCost(4),
		WithBcryptValidation(PasswordValidationOptions{MinLength: 1}),
	)

	password := []byte("SecurePass123")
	hash, err := hasher.Hash(ctx, password, PasswordOptions{})
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	t.Run("correct password", func(t *testing.T) {
		if err := hasher.Compare(ctx, password, hash); err != nil {
			t.Errorf("Compare() error = %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		err := hasher.Compare(ctx, []byte("wrongpass"), hash)
		if !errors.Is(err, ErrPasswordMismatch) {
			t.Errorf("Compare() error = %v, want ErrPasswordMismatch", err)
		}
	})

	t.Run("wrong algorithm", func(t *testing.T) {
		wrongHash := hash
		wrongHash.Algorithm = "other"
		err := hasher.Compare(ctx, password, wrongHash)
		if !errors.Is(err, ErrPasswordInvalidAlgorithm) {
			t.Errorf("Compare() error = %v, want ErrPasswordInvalidAlgorithm", err)
		}
	})

	t.Run("empty hash value", func(t *testing.T) {
		emptyHash := hash
		emptyHash.Value = nil
		err := hasher.Compare(ctx, password, emptyHash)
		if !errors.Is(err, ErrPasswordInvalidHash) {
			t.Errorf("Compare() error = %v, want ErrPasswordInvalidHash", err)
		}
	})

	t.Run("with pepper", func(t *testing.T) {
		pepper := []byte("server-secret")
		pepperedHasher := NewBcryptHasher(
			WithBcryptCost(4),
			WithBcryptPepper(pepper),
			WithBcryptValidation(PasswordValidationOptions{MinLength: 1}),
		)
		pepperedHash, _ := pepperedHasher.Hash(ctx, password, PasswordOptions{})

		// Should succeed with same pepper
		if err := pepperedHasher.Compare(ctx, password, pepperedHash); err != nil {
			t.Errorf("Compare() with pepper error = %v", err)
		}

		// Should fail without pepper
		noPepperHasher := NewBcryptHasher(WithBcryptCost(4))
		if err := noPepperHasher.Compare(ctx, password, pepperedHash); !errors.Is(err, ErrPasswordMismatch) {
			t.Errorf("Compare() without pepper should fail, got %v", err)
		}
	})
}

func TestBcryptHasher_NeedsRehash(t *testing.T) {
	now := time.Now()
	hasher := NewBcryptHasher(
		WithBcryptCost(12),
		WithBcryptMaxAge(24*time.Hour),
		WithBcryptNow(func() time.Time { return now }),
	)

	t.Run("lower cost needs rehash", func(t *testing.T) {
		hash := PasswordHash{
			Algorithm: AlgorithmBcrypt,
			Cost:      10,
			CreatedAt: now,
		}
		if !hasher.NeedsRehash(hash, PasswordOptions{}) {
			t.Error("NeedsRehash() should return true for lower cost")
		}
	})

	t.Run("same cost no rehash", func(t *testing.T) {
		hash := PasswordHash{
			Algorithm: AlgorithmBcrypt,
			Cost:      12,
			CreatedAt: now,
		}
		if hasher.NeedsRehash(hash, PasswordOptions{}) {
			t.Error("NeedsRehash() should return false for same cost")
		}
	})

	t.Run("expired hash needs rehash", func(t *testing.T) {
		hash := PasswordHash{
			Algorithm: AlgorithmBcrypt,
			Cost:      12,
			CreatedAt: now.Add(-48 * time.Hour),
		}
		if !hasher.NeedsRehash(hash, PasswordOptions{}) {
			t.Error("NeedsRehash() should return true for expired hash")
		}
	})

	t.Run("wrong algorithm needs rehash", func(t *testing.T) {
		hash := PasswordHash{
			Algorithm: "other",
			Cost:      12,
		}
		if !hasher.NeedsRehash(hash, PasswordOptions{}) {
			t.Error("NeedsRehash() should return true for wrong algorithm")
		}
	})

	t.Run("opts override", func(t *testing.T) {
		hash := PasswordHash{
			Algorithm: AlgorithmBcrypt,
			Cost:      10,
			CreatedAt: now,
		}
		// When opts.Cost is 10, cost 10 hash doesn't need rehash
		if hasher.NeedsRehash(hash, PasswordOptions{Cost: 10}) {
			t.Error("NeedsRehash() should respect opts.Cost")
		}
	})
}

func TestArgon2idHasher_Hash(t *testing.T) {
	ctx := context.Background()
	hasher := NewArgon2idHasher(
		WithArgon2Time(1),
		WithArgon2Memory(32*1024),
		WithArgon2Threads(2),
		WithArgon2Validation(PasswordValidationOptions{MinLength: 1}),
	)

	t.Run("valid password", func(t *testing.T) {
		hash, err := hasher.Hash(ctx, []byte("SecurePass123"), PasswordOptions{})
		if err != nil {
			t.Fatalf("Hash() error = %v", err)
		}
		if hash.Algorithm != AlgorithmArgon2id {
			t.Errorf("Algorithm = %s, want %s", hash.Algorithm, AlgorithmArgon2id)
		}
		if len(hash.Value) == 0 {
			t.Error("Hash value is empty")
		}
		if len(hash.Salt) == 0 {
			t.Error("Salt is empty")
		}
	})

	t.Run("with pepper", func(t *testing.T) {
		pepperedHasher := NewArgon2idHasher(
			WithArgon2Time(1),
			WithArgon2Memory(32*1024),
			WithArgon2Pepper([]byte("secret")),
			WithArgon2Validation(PasswordValidationOptions{MinLength: 1}),
		)
		hash, err := pepperedHasher.Hash(ctx, []byte("SecurePass123"), PasswordOptions{})
		if err != nil {
			t.Fatalf("Hash() with pepper error = %v", err)
		}
		if len(hash.Value) == 0 {
			t.Error("Hash value is empty")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := hasher.Hash(cancelledCtx, []byte("SecurePass123"), PasswordOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Hash() error = %v, want context.Canceled", err)
		}
	})
}

func TestArgon2idHasher_Compare(t *testing.T) {
	ctx := context.Background()
	hasher := NewArgon2idHasher(
		WithArgon2Time(1),
		WithArgon2Memory(32*1024),
		WithArgon2Threads(2),
		WithArgon2Validation(PasswordValidationOptions{MinLength: 1}),
	)

	password := []byte("SecurePass123")
	hash, err := hasher.Hash(ctx, password, PasswordOptions{})
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	t.Run("correct password", func(t *testing.T) {
		if err := hasher.Compare(ctx, password, hash); err != nil {
			t.Errorf("Compare() error = %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		err := hasher.Compare(ctx, []byte("wrongpass"), hash)
		if !errors.Is(err, ErrPasswordMismatch) {
			t.Errorf("Compare() error = %v, want ErrPasswordMismatch", err)
		}
	})

	t.Run("wrong algorithm", func(t *testing.T) {
		wrongHash := hash
		wrongHash.Algorithm = "bcrypt"
		err := hasher.Compare(ctx, password, wrongHash)
		if !errors.Is(err, ErrPasswordInvalidAlgorithm) {
			t.Errorf("Compare() error = %v, want ErrPasswordInvalidAlgorithm", err)
		}
	})

	t.Run("empty hash value", func(t *testing.T) {
		emptyHash := hash
		emptyHash.Value = nil
		err := hasher.Compare(ctx, password, emptyHash)
		if !errors.Is(err, ErrPasswordInvalidHash) {
			t.Errorf("Compare() error = %v, want ErrPasswordInvalidHash", err)
		}
	})

	t.Run("corrupted hash value", func(t *testing.T) {
		corruptedHash := hash
		corruptedHash.Value = []byte("invalid-hash-format")
		err := hasher.Compare(ctx, password, corruptedHash)
		if !errors.Is(err, ErrPasswordInvalidHash) {
			t.Errorf("Compare() error = %v, want ErrPasswordInvalidHash", err)
		}
	})

	t.Run("with pepper", func(t *testing.T) {
		pepper := []byte("server-secret")
		pepperedHasher := NewArgon2idHasher(
			WithArgon2Time(1),
			WithArgon2Memory(32*1024),
			WithArgon2Pepper(pepper),
			WithArgon2Validation(PasswordValidationOptions{MinLength: 1}),
		)
		pepperedHash, _ := pepperedHasher.Hash(ctx, password, PasswordOptions{})

		// Should succeed with same pepper
		if err := pepperedHasher.Compare(ctx, password, pepperedHash); err != nil {
			t.Errorf("Compare() with pepper error = %v", err)
		}

		// Should fail without pepper
		noPepperHasher := NewArgon2idHasher(
			WithArgon2Time(1),
			WithArgon2Memory(32*1024),
			WithArgon2Validation(PasswordValidationOptions{MinLength: 1}),
		)
		if err := noPepperHasher.Compare(ctx, password, pepperedHash); !errors.Is(err, ErrPasswordMismatch) {
			t.Errorf("Compare() without pepper should fail, got %v", err)
		}
	})
}

func TestArgon2idHasher_NeedsRehash(t *testing.T) {
	now := time.Now()
	hasher := NewArgon2idHasher(
		WithArgon2Time(3),
		WithArgon2Memory(64*1024),
		WithArgon2Threads(4),
		WithArgon2MaxAge(24*time.Hour),
		WithArgon2Now(func() time.Time { return now }),
		WithArgon2Validation(PasswordValidationOptions{MinLength: 1}),
	)

	ctx := context.Background()

	t.Run("lower time needs rehash", func(t *testing.T) {
		lowTimeHasher := NewArgon2idHasher(
			WithArgon2Time(1),
			WithArgon2Memory(64*1024),
			WithArgon2Threads(4),
			WithArgon2Validation(PasswordValidationOptions{MinLength: 1}),
		)
		hash, _ := lowTimeHasher.Hash(ctx, []byte("SecurePass123"), PasswordOptions{})

		if !hasher.NeedsRehash(hash, PasswordOptions{}) {
			t.Error("NeedsRehash() should return true for lower time")
		}
	})

	t.Run("same params no rehash", func(t *testing.T) {
		hash, _ := hasher.Hash(ctx, []byte("SecurePass123"), PasswordOptions{})
		hash.CreatedAt = now

		if hasher.NeedsRehash(hash, PasswordOptions{}) {
			t.Error("NeedsRehash() should return false for same params")
		}
	})

	t.Run("expired hash needs rehash", func(t *testing.T) {
		hash, _ := hasher.Hash(ctx, []byte("SecurePass123"), PasswordOptions{})
		hash.CreatedAt = now.Add(-48 * time.Hour)

		if !hasher.NeedsRehash(hash, PasswordOptions{}) {
			t.Error("NeedsRehash() should return true for expired hash")
		}
	})

	t.Run("wrong algorithm needs rehash", func(t *testing.T) {
		hash := PasswordHash{
			Algorithm: AlgorithmBcrypt,
		}
		if !hasher.NeedsRehash(hash, PasswordOptions{}) {
			t.Error("NeedsRehash() should return true for wrong algorithm")
		}
	})
}

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"hello", "hello", true},
		{"hello", "world", false},
		{"hello", "hell", false},
		{"", "", true},
		{"a", "", false},
		{"", "a", false},
		{"password", "password", true},
		{"password", "passwor", false},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			if got := SecureCompare(tt.a, tt.b); got != tt.want {
				t.Errorf("SecureCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSecureCompareBytes(t *testing.T) {
	tests := []struct {
		a, b []byte
		want bool
	}{
		{[]byte("hello"), []byte("hello"), true},
		{[]byte("hello"), []byte("world"), false},
		{[]byte("hello"), []byte("hell"), false},
		{nil, nil, true},
		{[]byte{}, []byte{}, true},
		{[]byte("a"), nil, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.a)+"_"+string(tt.b), func(t *testing.T) {
			if got := SecureCompareBytes(tt.a, tt.b); got != tt.want {
				t.Errorf("SecureCompareBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		email string
		valid bool
	}{
		{"test@example.com", true},
		{"user.name@domain.org", true},
		{"user+tag@example.co.uk", true},
		{"user@sub.domain.com", true},
		{"", false},
		{"invalid", false},
		{"@example.com", false},
		{"user@", false},
		{"user@.com", false},
		{"user@domain", false},
		{strings.Repeat("a", 300) + "@example.com", false},
		{"user name@example.com", false},
		{"user@example..com", false},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			if got := ValidateEmail(tt.email); got != tt.valid {
				t.Errorf("ValidateEmail(%q) = %v, want %v", tt.email, got, tt.valid)
			}
		})
	}
}

func TestGenerateSecureToken(t *testing.T) {
	t.Run("default length", func(t *testing.T) {
		token, err := GenerateSecureToken(0)
		if err != nil {
			t.Fatalf("GenerateSecureToken() error = %v", err)
		}
		if len(token) == 0 {
			t.Error("token is empty")
		}
	})

	t.Run("custom length", func(t *testing.T) {
		token, err := GenerateSecureToken(64)
		if err != nil {
			t.Fatalf("GenerateSecureToken() error = %v", err)
		}
		if len(token) == 0 {
			t.Error("token is empty")
		}
	})

	t.Run("uniqueness", func(t *testing.T) {
		tokens := make(map[string]struct{})
		for i := 0; i < 100; i++ {
			token, _ := GenerateSecureToken(32)
			if _, exists := tokens[token]; exists {
				t.Error("duplicate token generated")
			}
			tokens[token] = struct{}{}
		}
	})
}

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"  hello  ", "hello"},
		{"hello\x00world", "helloworld"},
		{"hello\x01world", "helloworld"},
		{"hello\tworld", "hello\tworld"},
		{"hello\nworld", "hello\nworld"},
		{"hello\rworld", "hello\rworld"},
		{"\x00\x01\x02hello\x03", "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := SanitizeInput(tt.input); got != tt.want {
				t.Errorf("SanitizeInput() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCommonPasswordDetection(t *testing.T) {
	common := []string{
		"password",
		"Password123",
		"12345678",
		"qwerty",
		"admin123",
		"letmein",
		"welcome",
	}

	for _, pw := range common {
		t.Run(pw, func(t *testing.T) {
			if !isCommonPassword(pw) {
				t.Errorf("isCommonPassword(%q) should return true", pw)
			}
		})
	}

	notCommon := []string{
		"xK9$mPq2#nL5",
		"MyUnique!Pass99",
		"r4nd0m$tr1ng",
	}

	for _, pw := range notCommon {
		t.Run(pw, func(t *testing.T) {
			if isCommonPassword(pw) {
				t.Errorf("isCommonPassword(%q) should return false", pw)
			}
		})
	}
}

func TestIsSequentialPattern(t *testing.T) {
	sequential := []string{
		"1234",
		"abcdef",
		"ABCD",
		"4321",
		"dcba",
	}

	for _, s := range sequential {
		t.Run(s, func(t *testing.T) {
			if !isSequentialPattern(s) {
				t.Errorf("isSequentialPattern(%q) should return true", s)
			}
		})
	}

	notSequential := []string{
		"abc",  // too short
		"1357", // not consecutive
		"aceg",
		"hello",
	}

	for _, s := range notSequential {
		t.Run(s, func(t *testing.T) {
			if isSequentialPattern(s) {
				t.Errorf("isSequentialPattern(%q) should return false", s)
			}
		})
	}
}

func TestIsRepeatingPattern(t *testing.T) {
	repeating := []string{
		"aaaa",
		"11111",
		"AAAAAAA",
	}

	for _, s := range repeating {
		t.Run(s, func(t *testing.T) {
			if !isRepeatingPattern(s) {
				t.Errorf("isRepeatingPattern(%q) should return true", s)
			}
		})
	}

	notRepeating := []string{
		"aaa",  // too short
		"aab",
		"hello",
		"1234",
	}

	for _, s := range notRepeating {
		t.Run(s, func(t *testing.T) {
			if isRepeatingPattern(s) {
				t.Errorf("isRepeatingPattern(%q) should return false", s)
			}
		})
	}
}

func TestClearBytes(t *testing.T) {
	b := []byte("secret-data")
	original := append([]byte(nil), b...)

	clearBytes(b)

	for i, v := range b {
		if v != 0 {
			t.Errorf("clearBytes() byte %d = %d, want 0", i, v)
		}
	}

	// Ensure original wasn't affected
	if string(original) != "secret-data" {
		t.Error("original slice was modified")
	}
}

// Benchmark tests
func BenchmarkBcryptHash(b *testing.B) {
	ctx := context.Background()
	hasher := NewBcryptHasher(
		WithBcryptCost(10),
		WithBcryptValidation(PasswordValidationOptions{MinLength: 1}),
	)
	password := []byte("SecurePassword123!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hasher.Hash(ctx, password, PasswordOptions{})
	}
}

func BenchmarkBcryptCompare(b *testing.B) {
	ctx := context.Background()
	hasher := NewBcryptHasher(
		WithBcryptCost(10),
		WithBcryptValidation(PasswordValidationOptions{MinLength: 1}),
	)
	password := []byte("SecurePassword123!")
	hash, _ := hasher.Hash(ctx, password, PasswordOptions{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hasher.Compare(ctx, password, hash)
	}
}

func BenchmarkArgon2idHash(b *testing.B) {
	ctx := context.Background()
	hasher := NewArgon2idHasher(
		WithArgon2Time(1),
		WithArgon2Memory(32*1024),
		WithArgon2Threads(2),
		WithArgon2Validation(PasswordValidationOptions{MinLength: 1}),
	)
	password := []byte("SecurePassword123!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hasher.Hash(ctx, password, PasswordOptions{})
	}
}

func BenchmarkArgon2idCompare(b *testing.B) {
	ctx := context.Background()
	hasher := NewArgon2idHasher(
		WithArgon2Time(1),
		WithArgon2Memory(32*1024),
		WithArgon2Threads(2),
		WithArgon2Validation(PasswordValidationOptions{MinLength: 1}),
	)
	password := []byte("SecurePassword123!")
	hash, _ := hasher.Hash(ctx, password, PasswordOptions{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hasher.Compare(ctx, password, hash)
	}
}

func BenchmarkSecureCompare(b *testing.B) {
	a := "this-is-a-secure-token-1234567890"
	c := "this-is-a-secure-token-1234567890"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SecureCompare(a, c)
	}
}

func BenchmarkValidatePasswordStrength(b *testing.B) {
	password := []byte("SecurePassword123!")
	opts := DefaultPasswordValidation()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidatePasswordStrength(password, opts)
	}
}
