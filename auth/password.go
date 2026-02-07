package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordTooShort         = errors.New("auth: password too short")
	ErrPasswordTooLong          = errors.New("auth: password too long")
	ErrPasswordNoUppercase      = errors.New("auth: password must contain uppercase letter")
	ErrPasswordNoLowercase      = errors.New("auth: password must contain lowercase letter")
	ErrPasswordNoDigit          = errors.New("auth: password must contain digit")
	ErrPasswordNoSpecial        = errors.New("auth: password must contain special character")
	ErrPasswordCommon           = errors.New("auth: password is too common")
	ErrPasswordMismatch         = errors.New("auth: password does not match")
	ErrPasswordInvalidAlgorithm = errors.New("auth: unsupported password algorithm")
	ErrPasswordInvalidHash      = errors.New("auth: invalid password hash")
	ErrPasswordHashExpired      = errors.New("auth: password hash expired")
)

// Password algorithm constants
const (
	AlgorithmBcrypt   = "bcrypt"
	AlgorithmArgon2id = "argon2id"
)

// Default password hashing parameters
const (
	DefaultBcryptCost     = 12
	DefaultArgon2Time     = 3
	DefaultArgon2Memory   = 64 * 1024 // 64 MB
	DefaultArgon2Threads  = 4
	DefaultArgon2KeyLen   = 32
	DefaultSaltLength     = 16
	MinPasswordLength     = 8
	MaxPasswordLength     = 128
	RecommendedMinLength  = 12
)

// PasswordValidationOptions configures password strength requirements.
type PasswordValidationOptions struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
	CheckCommon      bool
}

// DefaultPasswordValidation returns secure default password validation options.
func DefaultPasswordValidation() PasswordValidationOptions {
	return PasswordValidationOptions{
		MinLength:        MinPasswordLength,
		MaxLength:        MaxPasswordLength,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   false, // Optional by default, can be enabled
		CheckCommon:      true,
	}
}

// StrictPasswordValidation returns strict validation for high-security environments.
func StrictPasswordValidation() PasswordValidationOptions {
	return PasswordValidationOptions{
		MinLength:        RecommendedMinLength,
		MaxLength:        MaxPasswordLength,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
		CheckCommon:      true,
	}
}

// ValidatePasswordStrength checks password against validation rules.
func ValidatePasswordStrength(password []byte, opts PasswordValidationOptions) error {
	if len(password) == 0 {
		return ErrPasswordTooShort
	}

	s := string(password)
	length := len([]rune(s))

	minLen := opts.MinLength
	if minLen <= 0 {
		minLen = MinPasswordLength
	}
	maxLen := opts.MaxLength
	if maxLen <= 0 {
		maxLen = MaxPasswordLength
	}

	if length < minLen {
		return ErrPasswordTooShort
	}
	if length > maxLen {
		return ErrPasswordTooLong
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if opts.RequireUppercase && !hasUpper {
		return ErrPasswordNoUppercase
	}
	if opts.RequireLowercase && !hasLower {
		return ErrPasswordNoLowercase
	}
	if opts.RequireDigit && !hasDigit {
		return ErrPasswordNoDigit
	}
	if opts.RequireSpecial && !hasSpecial {
		return ErrPasswordNoSpecial
	}

	if opts.CheckCommon && isCommonPassword(s) {
		return ErrPasswordCommon
	}

	return nil
}

// BcryptHasher implements PasswordHasher using bcrypt.
type BcryptHasher struct {
	cost       int
	saltLength int
	pepper     []byte
	maxAge     time.Duration
	now        func() time.Time
	validation PasswordValidationOptions
}

// BcryptHasherOption configures BcryptHasher.
type BcryptHasherOption func(*BcryptHasher)

// WithBcryptCost sets the bcrypt cost factor.
func WithBcryptCost(cost int) BcryptHasherOption {
	return func(h *BcryptHasher) {
		if cost >= bcrypt.MinCost && cost <= bcrypt.MaxCost {
			h.cost = cost
		}
	}
}

// WithBcryptPepper sets a server-side secret that is combined with passwords.
func WithBcryptPepper(pepper []byte) BcryptHasherOption {
	return func(h *BcryptHasher) {
		h.pepper = append([]byte(nil), pepper...)
	}
}

// WithBcryptMaxAge sets the maximum age before a hash needs re-hashing.
func WithBcryptMaxAge(d time.Duration) BcryptHasherOption {
	return func(h *BcryptHasher) {
		if d > 0 {
			h.maxAge = d
		}
	}
}

// WithBcryptValidation sets password validation options.
func WithBcryptValidation(opts PasswordValidationOptions) BcryptHasherOption {
	return func(h *BcryptHasher) {
		h.validation = opts
	}
}

// WithBcryptNow sets a custom time function for testing.
func WithBcryptNow(fn func() time.Time) BcryptHasherOption {
	return func(h *BcryptHasher) {
		if fn != nil {
			h.now = fn
		}
	}
}

// NewBcryptHasher creates a new bcrypt-based password hasher.
func NewBcryptHasher(opts ...BcryptHasherOption) *BcryptHasher {
	h := &BcryptHasher{
		cost:       DefaultBcryptCost,
		saltLength: DefaultSaltLength,
		now:        time.Now,
		validation: DefaultPasswordValidation(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
	return h
}

// Hash generates a bcrypt hash for the given password.
func (h *BcryptHasher) Hash(ctx context.Context, plain []byte, opts PasswordOptions) (PasswordHash, error) {
	if err := contextError(ctx); err != nil {
		return PasswordHash{}, err
	}

	if err := ValidatePasswordStrength(plain, h.validation); err != nil {
		return PasswordHash{}, err
	}

	cost := h.cost
	if opts.Cost > 0 && opts.Cost >= bcrypt.MinCost && opts.Cost <= bcrypt.MaxCost {
		cost = opts.Cost
	}

	// Generate salt for metadata (bcrypt generates its own internally)
	salt := make([]byte, h.saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return PasswordHash{}, fmt.Errorf("auth: failed to generate salt: %w", err)
	}

	// Combine password with pepper if set
	combined := h.combineWithPepper(plain)
	defer clearBytes(combined)

	hashed, err := bcrypt.GenerateFromPassword(combined, cost)
	if err != nil {
		return PasswordHash{}, fmt.Errorf("auth: bcrypt hash failed: %w", err)
	}

	return PasswordHash{
		Algorithm: AlgorithmBcrypt,
		Cost:      cost,
		Salt:      salt,
		Value:     hashed,
		CreatedAt: h.now(),
	}, nil
}

// Compare validates a password against a stored hash.
func (h *BcryptHasher) Compare(ctx context.Context, plain []byte, hash PasswordHash) error {
	if err := contextError(ctx); err != nil {
		return err
	}

	if hash.Algorithm != AlgorithmBcrypt {
		return ErrPasswordInvalidAlgorithm
	}
	if len(hash.Value) == 0 {
		return ErrPasswordInvalidHash
	}

	combined := h.combineWithPepper(plain)
	defer clearBytes(combined)

	if err := bcrypt.CompareHashAndPassword(hash.Value, combined); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrPasswordMismatch
		}
		return fmt.Errorf("auth: bcrypt compare failed: %w", err)
	}

	return nil
}

// NeedsRehash returns true if the hash should be re-generated.
func (h *BcryptHasher) NeedsRehash(hash PasswordHash, opts PasswordOptions) bool {
	if hash.Algorithm != AlgorithmBcrypt {
		return true
	}

	targetCost := h.cost
	if opts.Cost > 0 {
		targetCost = opts.Cost
	}
	if hash.Cost < targetCost {
		return true
	}

	maxAge := h.maxAge
	if opts.MaxAge > 0 {
		maxAge = opts.MaxAge
	}
	if maxAge > 0 && !hash.CreatedAt.IsZero() {
		if h.now().Sub(hash.CreatedAt) > maxAge {
			return true
		}
	}

	return false
}

func (h *BcryptHasher) combineWithPepper(plain []byte) []byte {
	if len(h.pepper) == 0 {
		return append([]byte(nil), plain...)
	}
	combined := make([]byte, len(plain)+len(h.pepper))
	copy(combined, plain)
	copy(combined[len(plain):], h.pepper)
	return combined
}

// Argon2idHasher implements PasswordHasher using Argon2id.
type Argon2idHasher struct {
	time       uint32
	memory     uint32
	threads    uint8
	keyLen     uint32
	saltLength int
	pepper     []byte
	maxAge     time.Duration
	now        func() time.Time
	validation PasswordValidationOptions
}

// Argon2idHasherOption configures Argon2idHasher.
type Argon2idHasherOption func(*Argon2idHasher)

// WithArgon2Time sets the time parameter (iterations).
func WithArgon2Time(t uint32) Argon2idHasherOption {
	return func(h *Argon2idHasher) {
		if t > 0 {
			h.time = t
		}
	}
}

// WithArgon2Memory sets the memory parameter in KB.
func WithArgon2Memory(m uint32) Argon2idHasherOption {
	return func(h *Argon2idHasher) {
		if m > 0 {
			h.memory = m
		}
	}
}

// WithArgon2Threads sets the parallelism parameter.
func WithArgon2Threads(t uint8) Argon2idHasherOption {
	return func(h *Argon2idHasher) {
		if t > 0 {
			h.threads = t
		}
	}
}

// WithArgon2KeyLen sets the output key length.
func WithArgon2KeyLen(l uint32) Argon2idHasherOption {
	return func(h *Argon2idHasher) {
		if l > 0 {
			h.keyLen = l
		}
	}
}

// WithArgon2Pepper sets a server-side secret.
func WithArgon2Pepper(pepper []byte) Argon2idHasherOption {
	return func(h *Argon2idHasher) {
		h.pepper = append([]byte(nil), pepper...)
	}
}

// WithArgon2MaxAge sets the maximum age before a hash needs re-hashing.
func WithArgon2MaxAge(d time.Duration) Argon2idHasherOption {
	return func(h *Argon2idHasher) {
		if d > 0 {
			h.maxAge = d
		}
	}
}

// WithArgon2Validation sets password validation options.
func WithArgon2Validation(opts PasswordValidationOptions) Argon2idHasherOption {
	return func(h *Argon2idHasher) {
		h.validation = opts
	}
}

// WithArgon2Now sets a custom time function for testing.
func WithArgon2Now(fn func() time.Time) Argon2idHasherOption {
	return func(h *Argon2idHasher) {
		if fn != nil {
			h.now = fn
		}
	}
}

// NewArgon2idHasher creates a new Argon2id-based password hasher.
func NewArgon2idHasher(opts ...Argon2idHasherOption) *Argon2idHasher {
	h := &Argon2idHasher{
		time:       DefaultArgon2Time,
		memory:     DefaultArgon2Memory,
		threads:    DefaultArgon2Threads,
		keyLen:     DefaultArgon2KeyLen,
		saltLength: DefaultSaltLength,
		now:        time.Now,
		validation: DefaultPasswordValidation(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
	return h
}

// Hash generates an Argon2id hash for the given password.
func (h *Argon2idHasher) Hash(ctx context.Context, plain []byte, opts PasswordOptions) (PasswordHash, error) {
	if err := contextError(ctx); err != nil {
		return PasswordHash{}, err
	}

	if err := ValidatePasswordStrength(plain, h.validation); err != nil {
		return PasswordHash{}, err
	}

	saltLen := h.saltLength
	if opts.SaltLength > 0 {
		saltLen = opts.SaltLength
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return PasswordHash{}, fmt.Errorf("auth: failed to generate salt: %w", err)
	}

	combined := h.combineWithPepper(plain)
	defer clearBytes(combined)

	hash := argon2.IDKey(combined, salt, h.time, h.memory, h.threads, h.keyLen)

	// Encode parameters in the hash value for verification
	encoded := h.encodeHash(salt, hash)

	return PasswordHash{
		Algorithm: AlgorithmArgon2id,
		Cost:      int(h.time),
		Salt:      salt,
		Value:     encoded,
		CreatedAt: h.now(),
	}, nil
}

// Compare validates a password against a stored hash.
func (h *Argon2idHasher) Compare(ctx context.Context, plain []byte, hash PasswordHash) error {
	if err := contextError(ctx); err != nil {
		return err
	}

	if hash.Algorithm != AlgorithmArgon2id {
		return ErrPasswordInvalidAlgorithm
	}
	if len(hash.Value) == 0 {
		return ErrPasswordInvalidHash
	}

	params, storedHash, err := h.decodeHash(hash.Value)
	if err != nil {
		return err
	}

	combined := h.combineWithPepper(plain)
	defer clearBytes(combined)

	computedHash := argon2.IDKey(combined, hash.Salt, params.time, params.memory, params.threads, params.keyLen)

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(computedHash, storedHash) != 1 {
		return ErrPasswordMismatch
	}

	return nil
}

// NeedsRehash returns true if the hash should be re-generated.
func (h *Argon2idHasher) NeedsRehash(hash PasswordHash, opts PasswordOptions) bool {
	if hash.Algorithm != AlgorithmArgon2id {
		return true
	}

	params, _, err := h.decodeHash(hash.Value)
	if err != nil {
		return true
	}

	// Check if parameters have changed
	if params.time < h.time || params.memory < h.memory || params.threads < h.threads {
		return true
	}

	maxAge := h.maxAge
	if opts.MaxAge > 0 {
		maxAge = opts.MaxAge
	}
	if maxAge > 0 && !hash.CreatedAt.IsZero() {
		if h.now().Sub(hash.CreatedAt) > maxAge {
			return true
		}
	}

	return false
}

type argon2Params struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func (h *Argon2idHasher) encodeHash(salt, hash []byte) []byte {
	// Format: $argon2id$v=19$m=MEMORY,t=TIME,p=THREADS$SALT$HASH
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.time, h.threads, b64Salt, b64Hash)
	return []byte(encoded)
}

func (h *Argon2idHasher) decodeHash(encoded []byte) (argon2Params, []byte, error) {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 6 {
		return argon2Params{}, nil, ErrPasswordInvalidHash
	}

	if parts[1] != "argon2id" {
		return argon2Params{}, nil, ErrPasswordInvalidAlgorithm
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argon2Params{}, nil, ErrPasswordInvalidHash
	}

	var params argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.time, &params.threads); err != nil {
		return argon2Params{}, nil, ErrPasswordInvalidHash
	}
	params.keyLen = h.keyLen

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2Params{}, nil, ErrPasswordInvalidHash
	}

	return params, hash, nil
}

func (h *Argon2idHasher) combineWithPepper(plain []byte) []byte {
	if len(h.pepper) == 0 {
		return append([]byte(nil), plain...)
	}
	combined := make([]byte, len(plain)+len(h.pepper))
	copy(combined, plain)
	copy(combined[len(plain):], h.pepper)
	return combined
}

// clearBytes securely zeros a byte slice.
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Common passwords list (top 100 most common)
var commonPasswords = map[string]struct{}{
	"123456":          {},
	"password":        {},
	"12345678":        {},
	"qwerty":          {},
	"123456789":       {},
	"12345":           {},
	"1234":            {},
	"111111":          {},
	"1234567":         {},
	"dragon":          {},
	"123123":          {},
	"baseball":        {},
	"abc123":          {},
	"football":        {},
	"monkey":          {},
	"letmein":         {},
	"shadow":          {},
	"master":          {},
	"666666":          {},
	"qwertyuiop":      {},
	"123321":          {},
	"mustang":         {},
	"1234567890":      {},
	"michael":         {},
	"654321":          {},
	"superman":        {},
	"1qaz2wsx":        {},
	"7777777":         {},
	"121212":          {},
	"000000":          {},
	"qazwsx":          {},
	"123qwe":          {},
	"killer":          {},
	"trustno1":        {},
	"jordan":          {},
	"jennifer":        {},
	"zxcvbnm":         {},
	"asdfgh":          {},
	"hunter":          {},
	"buster":          {},
	"soccer":          {},
	"harley":          {},
	"batman":          {},
	"andrew":          {},
	"tigger":          {},
	"sunshine":        {},
	"iloveyou":        {},
	"2000":            {},
	"charlie":         {},
	"robert":          {},
	"thomas":          {},
	"hockey":          {},
	"ranger":          {},
	"daniel":          {},
	"starwars":        {},
	"klaster":         {},
	"112233":          {},
	"george":          {},
	"computer":        {},
	"michelle":        {},
	"jessica":         {},
	"pepper":          {},
	"1111":            {},
	"zxcvbn":          {},
	"555555":          {},
	"11111111":        {},
	"131313":          {},
	"freedom":         {},
	"777777":          {},
	"pass":            {},
	"maggie":          {},
	"159753":          {},
	"aaaaaa":          {},
	"ginger":          {},
	"princess":        {},
	"joshua":          {},
	"cheese":          {},
	"amanda":          {},
	"summer":          {},
	"love":            {},
	"ashley":          {},
	"nicole":          {},
	"chelsea":         {},
	"biteme":          {},
	"matthew":         {},
	"access":          {},
	"yankees":         {},
	"987654321":       {},
	"dallas":          {},
	"austin":          {},
	"thunder":         {},
	"taylor":          {},
	"matrix":          {},
	"mobilemail":      {},
	"mom":             {},
	"monitor":         {},
	"monitoring":      {},
	"montana":         {},
	"moon":            {},
	"moscow":          {},
	"password1":       {},
	"password123":     {},
	"passw0rd":        {},
	"Password1":       {},
	"Password123":     {},
	"admin":           {},
	"administrator":   {},
	"root":            {},
	"toor":            {},
	"pass123":         {},
	"test":            {},
	"guest":           {},
	"master123":       {},
	"changeme":        {},
	"qwerty123":       {},
	"welcome":         {},
	"welcome1":        {},
	"welcome123":      {},
	"p@ssw0rd":        {},
	"p@ssword":        {},
	"P@ssw0rd":        {},
	"P@ssword1":       {},
	"Password1!":      {},
	"Passw0rd!":       {},
	"letmein123":      {},
	"abc123456":       {},
	"admin123":        {},
	"Admin123":        {},
	"123456789a":      {},
	"a123456789":      {},
	"1q2w3e4r":        {},
	"1q2w3e4r5t":      {},
	"q1w2e3r4":        {},
	"q1w2e3r4t5":      {},
	"qweasd":          {},
	"qweasdzxc":       {},
	"asdfghjkl":       {},
	"zxcvbnm123":      {},
	"1234qwer":        {},
	"qwer1234":        {},
	"abcd1234":        {},
	"1234abcd":        {},
	"Password":        {},
	"password!":       {},
	"password1!":      {},
}

// isCommonPassword checks if the password is in the common passwords list.
func isCommonPassword(password string) bool {
	lower := strings.ToLower(password)
	if _, ok := commonPasswords[password]; ok {
		return true
	}
	if _, ok := commonPasswords[lower]; ok {
		return true
	}
	// Check for simple patterns
	if isSequentialPattern(password) {
		return true
	}
	if isRepeatingPattern(password) {
		return true
	}
	return false
}

// isSequentialPattern checks for sequential characters like "123456" or "abcdef"
func isSequentialPattern(s string) bool {
	if len(s) < 4 {
		return false
	}
	ascending := true
	descending := true
	runes := []rune(s)
	for i := 1; i < len(runes); i++ {
		diff := int(runes[i]) - int(runes[i-1])
		if diff != 1 {
			ascending = false
		}
		if diff != -1 {
			descending = false
		}
	}
	return ascending || descending
}

// isRepeatingPattern checks for repeating characters like "aaaaaa"
func isRepeatingPattern(s string) bool {
	if len(s) < 4 {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

// Email validation regex
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ValidateEmail validates an email address format.
func ValidateEmail(email string) bool {
	email = strings.TrimSpace(email)
	if len(email) == 0 || len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}

// SecureCompare performs constant-time string comparison to prevent timing attacks.
func SecureCompare(a, b string) bool {
	if len(a) != len(b) {
		// Still do the comparison to maintain constant time
		subtle.ConstantTimeCompare([]byte(a), []byte(a))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SecureCompareBytes performs constant-time byte slice comparison.
func SecureCompareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		subtle.ConstantTimeCompare(a, a)
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// GenerateSecureToken generates a cryptographically secure random token.
func GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		length = 32
	}
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("auth: failed to generate secure token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SanitizeInput removes potentially dangerous characters from input.
func SanitizeInput(s string) string {
	// Remove null bytes and control characters
	var buf bytes.Buffer
	for _, r := range s {
		if r == 0 || (r < 32 && r != '\t' && r != '\n' && r != '\r') {
			continue
		}
		buf.WriteRune(r)
	}
	return strings.TrimSpace(buf.String())
}
