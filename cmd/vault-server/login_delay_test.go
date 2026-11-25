package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRandomLoginDelayIsBetweenThreeAndFiveSeconds(t *testing.T) {
	for i := 0; i < 100; i++ {
		delay, err := randomLoginDelayDuration()
		if err != nil {
			t.Fatal(err)
		}
		if delay < 3*time.Second || delay > 5*time.Second {
			t.Fatalf("login delay = %s, want 3-5 seconds", delay)
		}
	}
}

func TestLoginDelayStopsWhenRequestContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitRandomLoginDelay(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled login delay error = %v, want context.Canceled", err)
	}
}
