// Copyright 2017 the original author or authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net/http"

	"bytes"

	"github.com/gorilla/mux"
	"sync"
)

var configMutex sync.Mutex

type Listener struct {
	ListenOn string
	Update   chan []byte

	router        *mux.Router
	clusterConfig []byte
}

func (l *Listener) Init() {
	l.router = mux.NewRouter()
	l.router.HandleFunc("/config", l.ConfigHandler).Methods("GET")
	l.router.HandleFunc("/config/", l.ConfigHandler).Methods("GET")
	l.clusterConfig = []byte("{}")
	l.Update = make(chan []byte)
	go l.updateHandler()
}

func (l *Listener) updateHandler() {
	for {
		next := <-l.Update

		if !bytes.Equal(next, l.clusterConfig) {
			log.Info("Cluster configuration modified")
			configMutex.Lock()
			l.clusterConfig = next
			configMutex.Unlock()
		} else {
			log.Debug("Cluster update received, w/o change")
		}
	}
}

func (l *Listener) ListenAndServe() error {
	log.Infof("Starting to listen for cluster configuration requests on '%s'",
		l.ListenOn)
	return http.ListenAndServe(l.ListenOn, l.router)
}

func (l *Listener) ConfigHandler(w http.ResponseWriter, r *http.Request) {
	configMutex.Lock()
	local := l.clusterConfig
	configMutex.Unlock()
	if len(local) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Add("content-type", "application/json")
	w.Write(local)
	return
}
