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
	"github.com/evalphobia/logrus_fluent"
	"github.com/sirupsen/logrus"
	"net"
	"strconv"
	"sync"
)

type logManager struct {
	*logrus.Logger
}

// Singleton instance
var mgrInstance *logManager
var once sync.Once

func (mgr *logManager) SetFluentd(fluentdHost string) {
	var hook *logrus_fluent.FluentHook
	var err error
	var host string
	var portStr string
	var port int

	if host, portStr, err = net.SplitHostPort(fluentdHost); err != nil {
		mgr.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to retrieve host/port information")
		return
	}

	if port, err = strconv.Atoi(portStr); err != nil {
		mgr.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to convert port to integer")
		return
	}

	if hook, err = logrus_fluent.NewWithConfig(
		logrus_fluent.Config{
			Host: host,
			Port: port,
		}); err != nil {
		mgr.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to enable Fluentd hook")
		return
	}

	hook.SetTag("ponsim")

	hook.SetLevels([]logrus.Level{
		logrus.DebugLevel,
	})

	mgr.AddHook(hook)

	mgr.WithFields(logrus.Fields{
		"hook": hook,
	}).Info("Added fluentd hook")
}

/**
 * Get instance
 *
 * It should get initialized only once
 */
func Logger() *logManager {
	once.Do(func() {

		_logger := logrus.New()
		_logger.Formatter = new(logrus.JSONFormatter)
		_logger.Level = logrus.DebugLevel
		//_logger.Out =

		mgrInstance = &logManager{_logger}
	})

	return mgrInstance
}
