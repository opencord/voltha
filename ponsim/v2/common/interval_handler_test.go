package common

import (
	"fmt"
	"testing"
	"time"
)

var (
	handler   *IntervalHandler
	iteration int = 0
	interval  int = 2
)

func RepeatMessage() {
	fmt.Printf("Ran the function %d times\n", iteration)
	iteration += 1
}

func TestNewIntervalHandler(t *testing.T) {
	handler = NewIntervalHandler(interval, RepeatMessage)

	if handler.state != STOPPED {
		t.Error("The handler should be in STOPPED state", handler.state)
	}
	if handler.Interval != interval {
		t.Error("The handler interval doesn't match the configured value", handler.Interval)
	}
	if handler.function == nil {
		t.Error("The handler does not have function configured function", handler.function)
	}
}

func TestIntervalHandler_Start(t *testing.T) {
	handler.Start()

	time.Sleep(5 * time.Second)

	if handler.state != STARTED {
		t.Error("The handler should be in STARTED state", handler.state)
	}
}

func TestIntervalHandler_Pause(t *testing.T) {
	handler.Pause()

	if handler.state != PAUSED {
		t.Error("The handler should be in PAUSED state", handler.state)
	}

	time.Sleep(5 * time.Second)
}

func TestIntervalHandler_Resume(t *testing.T) {
	handler.Resume()

	time.Sleep(5 * time.Second)

	if handler.state != STARTED {
		t.Error("The handler should be in STARTED state", handler.state)
	}
}

func TestIntervalHandler_Stop(t *testing.T) {
	handler.Stop()

	if handler.state != STOPPED {
		t.Error("The handler should be in STOPPED state", handler.state)
	}

	time.Sleep(5 * time.Second)
}
