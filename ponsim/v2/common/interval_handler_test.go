/*
 * Copyright 2017-present Open Networking Foundation

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
