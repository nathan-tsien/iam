package memory

import (
	"context"
	"sync"
	"time"
)

type entry struct {
	count     int64
	expiresAt time.Time
}

// Store is a goroutine-safe in-memory counter with per-key TTL.
type Store struct {
	mu   sync.Mutex
	data map[string]*entry
}

func NewStore() *Store {
	return &Store{data: make(map[string]*entry)}
}

func (s *Store) Incr(ctx context.Context, key string, ttlOnCreate time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	e, ok := s.data[key]
	if !ok || now.After(e.expiresAt) {
		e = &entry{count: 0, expiresAt: now.Add(ttlOnCreate)}
		s.data[key] = e
	}
	e.count++
	return e.count, nil
}

func (s *Store) Reset(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}
