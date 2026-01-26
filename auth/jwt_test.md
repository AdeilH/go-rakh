# JWT Test Guide

These notes cover the Redis-backed JWT test suite located in `auth/jwt_test.go`.

## Prerequisites
- Docker Engine 20.10+ (the tests build and run `Dockerfile.redis.test`).
- Go (matching the version in `go.mod`).

## Running the Suite
```bash
cd /home/Adeel/development/personal/go-rakh
go test ./auth
```
`TestMain` automatically builds the Redis image, runs it on `localhost:6390`, and tears it down after the suite finishes.

## What the Tests Cover
- `TestHMACJWTProviderIssueParse`: basic issuance + parse round trip.
- `TestHMACJWTProviderRevocation`: ensures revoked tokens fail parsing.
- `TestHMACJWTProviderCacheConsistency`: confirms cache entries are required for validity.
- `TestHMACJWTProviderTTLExpiry`: issues a short-lived token, waits for TTL expiry, asserts parsing fails with `ErrJWTExpired`/`ErrJWTRevoked`, and verifies Redis evicts the key.
- `TestJWTIntegrationRoundTrip`: end-to-end coverage of claims, options, redis persistence, and revocation.

## Debugging Tips
- Keep the container running for manual inspection:
  ```bash
  docker exec -it go-rakh-cache-redis-test redis-cli
  KEYS jwt*
  TTL jwt:<token-id>
  GET jwt:<token-id>
  ```
- Adjust `SetCachePrefix` in tests to isolate keys when debugging multiple runs.
- Use `provider.SetLeeway(0)` in focused tests if you need deterministic expiry timing.
