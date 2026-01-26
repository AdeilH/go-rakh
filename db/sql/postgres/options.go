package postgres

import "time"

// Options configures PostgreSQL connections and pool behavior.
type Options struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type Option func(*Options)

// WithDSN sets the lib/pq connection string.
func WithDSN(dsn string) Option {
	return func(o *Options) {
		if dsn != "" {
			o.DSN = dsn
		}
	}
}

// WithMaxOpenConns controls the maximum number of open connections.
func WithMaxOpenConns(n int) Option {
	return func(o *Options) {
		if n > 0 {
			o.MaxOpenConns = n
		}
	}
}

// WithMaxIdleConns controls the idle connection pool size.
func WithMaxIdleConns(n int) Option {
	return func(o *Options) {
		if n >= 0 {
			o.MaxIdleConns = n
		}
	}
}

// WithConnMaxLifetime controls how long a connection can be reused.
func WithConnMaxLifetime(d time.Duration) Option {
	return func(o *Options) {
		if d > 0 {
			o.ConnMaxLifetime = d
		}
	}
}

func defaultOptions() Options {
	return Options{
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 30 * time.Minute,
	}
}
