# Redis Cache Tests

This package ships Docker-backed integration tests that spin up a disposable Redis instance before exercising the custom RESP client.

## Requirements
- Docker Engine 20.10+
- Go toolchain (matches `go.mod`)

## Run the Redis Tests
From the repository root:

```bash
cd /home/Adeel/development/personal/go-rakh
go test ./cache/redis
```

The `TestMain` helper builds `Dockerfile.redis.test`, runs the container on port `6390`, waits for a successful `PING/PONG`, and shuts the container down after the suite finishes.

## Manual Redis Control (Optional)
If you want to poke around manually, use the same Dockerfile:

```bash
cd /home/Adeel/development/personal/go-rakh
docker build -f Dockerfile.redis.test -t go-rakh-cache-redis-test .
docker run -d --rm --name go-rakh-cache-redis-test -p 6390:6379 go-rakh-cache-redis-test
# ... run manual checks ...
docker stop go-rakh-cache-redis-test
```

These commands mirror what the tests perform automatically.
