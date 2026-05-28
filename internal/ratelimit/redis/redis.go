package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Store implements ratelimit.Store using Redis INCR + EXPIRE NX.
type Store struct {
	client *goredis.Client
}

func NewStore(client *goredis.Client) *Store {
	return &Store{client: client}
}

// Incr pipelines INCR + EXPIRE NX so the TTL is set only on the first increment.
func (s *Store) Incr(ctx context.Context, key string, ttlOnCreate time.Duration) (int64, error) {
	pipe := s.client.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.ExpireNX(ctx, key, ttlOnCreate)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

func (s *Store) Reset(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}
