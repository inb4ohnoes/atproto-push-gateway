package chat

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/dracoblue/atproto-push-gateway/internal/store"
)

type Coordinator struct {
	store        *store.Store
	poller       *Poller
	pollInterval time.Duration
	wake         chan struct{}
	stop         chan struct{}
	mu           sync.Mutex
	workers      map[string]context.CancelFunc
}

func NewCoordinator(s *store.Store, poller *Poller, pollInterval time.Duration) *Coordinator {
	if pollInterval <= 0 {
		pollInterval = 15 * time.Second
	}
	return &Coordinator{store: s, poller: poller, pollInterval: pollInterval, wake: make(chan struct{}, 1), stop: make(chan struct{}), workers: make(map[string]context.CancelFunc)}
}

func (c *Coordinator) NotifyEnrollmentChanged() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Coordinator) Run() {
	c.reconcile()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			c.stopWorkers()
			return
		case <-c.wake:
			c.reconcile()
		case <-ticker.C:
			c.reconcile()
		}
	}
}

func (c *Coordinator) Stop() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
}

func (c *Coordinator) reconcile() {
	enrollments, err := c.store.ListActiveDMEnrollments()
	if err != nil {
		log.Printf("[chat] enrollment reconciliation failed: %v", err)
		return
	}
	active := make(map[string]bool, len(enrollments))
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, enrollment := range enrollments {
		active[enrollment.ActorDID] = true
		if _, exists := c.workers[enrollment.ActorDID]; !exists {
			ctx, cancel := context.WithCancel(context.Background())
			c.workers[enrollment.ActorDID] = cancel
			go c.runAccount(ctx, enrollment.ActorDID)
		}
	}
	for actorDID, cancel := range c.workers {
		if !active[actorDID] {
			cancel()
			delete(c.workers, actorDID)
		}
	}
}

func (c *Coordinator) runAccount(ctx context.Context, actorDID string) {
	delay := time.Duration(0)
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		err := c.poller.PollOnce(ctx, actorDID)
		if ctx.Err() != nil || errors.Is(err, ErrNeedsReauth) {
			return
		}
		delay = nextPollDelay(delay, c.pollInterval, err)
		if err != nil {
			log.Printf("[chat] poll failed for %s; retrying in %s: %v", actorDID, delay, err)
		}
	}
}

func nextPollDelay(previous, normal time.Duration, err error) time.Duration {
	if err == nil {
		return normal
	}
	var statusError *HTTPStatusError
	if errors.As(err, &statusError) && statusError.RetryAfter > 0 {
		return statusError.RetryAfter
	}
	if previous < time.Second {
		return time.Second
	}
	delay := previous * 2
	if delay > time.Minute {
		return time.Minute
	}
	return delay
}

func (c *Coordinator) stopWorkers() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for actorDID, cancel := range c.workers {
		cancel()
		delete(c.workers, actorDID)
	}
}
