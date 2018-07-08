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
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

/*
 IntervalHandler is used to run a routine at regular intervals and provide all the necessary
 utilities to manage the execution.
*/

type IntervalHandler struct {
	// Interval period in between each execution (in seconds?)
	Interval int
	// function to execute after each interval
	function func()
	// Channel listening to execution events
	execute chan _ExecutionState
	// Channel listening for a termination event
	terminate chan struct{}
	// Current execution state of the handler
	state _ExecutionState
	wg    sync.WaitGroup
}

// Define execution state constants
type _ExecutionState uint8

const (
	STARTED _ExecutionState = iota
	STOPPED
	PAUSED
	RESUMED
)

// Execute state string equivalents
var _ExecutionStateEnum = []string{
	"STARTED",
	"STOPPED",
	"PAUSED",
	"RESUMED",
}

func (s _ExecutionState) String() string {
	return _ExecutionStateEnum[s]
}

/*
NewIntervalHandler instantiates a new interval based function execution handler
*/
func NewIntervalHandler(interval int, function func()) *IntervalHandler {
	handler := &IntervalHandler{
		Interval: interval,
		function: function,
	}

	handler.execute = make(chan _ExecutionState)
	handler.terminate = make(chan struct{})
	handler.state = STOPPED

	return handler
}

/*
_Execute is a routine running concurrently and listening to execution events
*/
func (h *IntervalHandler) _Execute() {
	defer h.wg.Done()
	for {
		select {
		case h.state = <-h.execute:
			Logger().WithFields(logrus.Fields{
				"handler": h,
			}).Debug("Processing execution state")
			switch h.state {
			case STARTED:
			case PAUSED:
			case RESUMED:
				h.state = STARTED
			case STOPPED:
				fallthrough
			default:
				h.terminate <- struct{}{}
			}

		case <-h.terminate:
			return

		default:
			if h.state == STARTED {
				h.function()
				time.Sleep(time.Duration(h.Interval) * time.Second)
			} else {
				// TODO: replace hardcoded delay with a configurable parameter
				time.Sleep(1 * time.Second)
			}
		}
	}
}

/*
Start initiates the interval based function execution
*/
func (h *IntervalHandler) Start() {
	Logger().WithFields(logrus.Fields{
		"handler": h,
	}).Info("Starting interval handler")

	if h.execute == nil {
		return
	}
	if h.state == STOPPED {
		go h._Execute()
		h.execute <- STARTED
	}
}

/*
Pause interrupts the interval based function execution
*/
func (h *IntervalHandler) Pause() {
	Logger().WithFields(logrus.Fields{
		"handler": h,
	}).Info("Pausing interval handler")

	if h.execute == nil || h.state == STOPPED {
		return
	}
	if h.state == STARTED {
		h.execute <- PAUSED
	}
}

/*
Resume continues the interval based function execution
*/
func (h *IntervalHandler) Resume() {
	Logger().WithFields(logrus.Fields{
		"handler": h,
	}).Info("Resuming interval handler")

	if h.execute == nil || h.state == STOPPED {
		return
	}
	if h.state == PAUSED {
		h.execute <- RESUMED
	}
}

/*
Stop terminates the interval based function execution
*/
func (h *IntervalHandler) Stop() {
	Logger().WithFields(logrus.Fields{
		"handler": h,
	}).Info("Stopping interval handler")

	if h.execute == nil || h.state == STOPPED {
		return
	}
	h.execute <- STOPPED
}
