package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

func randomLoginDelayDuration() (time.Duration, error) {
	randomMilliseconds, err := rand.Int(rand.Reader, big.NewInt(2001))
	if err != nil {
		return 0, fmt.Errorf("generate login delay: %w", err)
	}
	return 3*time.Second + time.Duration(randomMilliseconds.Int64())*time.Millisecond, nil
}

func waitRandomLoginDelay(ctx context.Context) error {
	delay, err := randomLoginDelayDuration()
	if err != nil {
		return err
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *server) delayLoginAction(w http.ResponseWriter, r *http.Request) bool {
	delay := s.loginDelay
	if delay == nil {
		delay = waitRandomLoginDelay
	}
	if err := delay(r.Context()); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return true
		}
		log.Printf("ERROR: could not delay login action: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not process login"})
		return true
	}
	return false
}
