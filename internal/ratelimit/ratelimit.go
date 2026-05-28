package ratelimit

import (
	"context"
	"time"
)

// Store is the minimum surface a rate limit backend must support.
type Store interface {
	Incr(ctx context.Context, key string, ttlOnCreate time.Duration) (int64, error)
	Reset(ctx context.Context, key string) error
}

// Allow returns (true, remaining, nil) when a request is within budget and
// (false, 0, nil) when exceeded.
func Allow(ctx context.Context, store Store, key string, max int64, window time.Duration) (bool, int64, error) {
	count, err := store.Incr(ctx, key, window)
	if err != nil {
		return false, 0, err
	}
	if count > max {
		return false, 0, nil
	}
	return true, max - count, nil
}
