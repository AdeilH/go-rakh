package redis

import "time"

// Options controls how the Redis cache store connects to the server.
type Options struct {
	Addr         string
	Password     string
	DB           int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolSize     int
}

func (o Options) withDefaults() Options {
	if o.Addr == "" {
		o.Addr = "127.0.0.1:6379"
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 5 * time.Second
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = 2 * time.Second
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 2 * time.Second
	}
	if o.DB < 0 {
		o.DB = 0
	}
	if o.PoolSize <= 0 {
		o.PoolSize = 8
	}
	return o
}
