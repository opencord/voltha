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
	"fmt"
	"net/url"
)

type ClusterInfo struct {
	Expected uint64
	Nodes    []string
}

type OrchestrationClient interface {
	Init(url *url.URL) error
	GetInfo(labels map[string]string, networkLabels map[string]string) (*ClusterInfo, error)
	Close() error
}

func NewOrchestrationClient(url *url.URL) (OrchestrationClient, error) {
	var client OrchestrationClient

	switch url.Scheme {
	case "swarm":
		client = &SwarmClient{}
	case "kubernetes":
		return nil, fmt.Errorf("Kubernetes is not yet supported")
	default:
		return nil, fmt.Errorf("Unknown container orchestrator, '%s' specified",
			url.Scheme)
	}

	err := client.Init(url)
	if err != nil {
		return nil, err
	}
	return client, nil
}
