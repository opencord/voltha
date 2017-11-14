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
	"context"
	"net"
	"net/url"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
)

type SwarmClient struct {
	client *client.Client
}

func (c *SwarmClient) Init(aurl *url.URL) error {
	var err error
	c.client, err = client.NewEnvClient()
	if err != nil {
		return err
	}

	return nil
}

func (c *SwarmClient) GetInfo(labels map[string]string, networkLabels map[string]string) (*ClusterInfo, error) {
	info := ClusterInfo{}

	nodeState := make(map[string]bool)

	services, err := c.client.ServiceList(context.Background(), types.ServiceListOptions{})
	if err != nil {
		log.Errorf("Error while quering services : %s", err.Error())
		return nil, err
	}

	tasks, err := c.client.TaskList(context.Background(), types.TaskListOptions{})
	if err != nil {
		log.Error("Error while quering tasks")
		return nil, err
	}

	nodes, err := c.client.NodeList(context.Background(), types.NodeListOptions{})
	if err != nil {
		log.Error("Error while quering nodes")
		return nil, err
	}

	for _, node := range nodes {
		nodeState[node.ID] = (node.Status.State == swarm.NodeStateReady)
		log.Debugf("NODE STATUS: %s : %t", node.ID, nodeState[node.ID])
	}

	log.Debugf("SERVICE COUNT: %d", len(services))
	for _, service := range services {
		log.Debugf("NAME: %s, WANT: %s, HAVE: %s", service.Spec.Name, labels, service.Spec.Labels)
		if labelMatch(service.Spec.Labels, labels) {
			log.Debugf("MATCH: NAME: %s, EXPECTED: %d", service.Spec.Name, *service.Spec.Mode.Replicated.Replicas)
			info.Expected += *service.Spec.Mode.Replicated.Replicas

			for _, task := range tasks {
				// If tasks is not associated with the matching serice, reject it
				if task.ServiceID != service.ID {
					continue
				}

				// If the task is not on a running node, reject it
				if !nodeState[task.NodeID] || task.Status.State != swarm.TaskStateRunning {
					log.Debugf("Found matching task '%s' [%s], on node '%s' [%t]",
						task.ID, task.Status.State, task.NodeID, nodeState[task.NodeID])
					continue
				}
				log.Debugf("Found matching task '%s' on node '%s', with a state of %s",
					task.ID, task.NodeID, task.Status.State)

				/*
				 * Need to discover an IP for the container to use for clustering
				 * purposes. The search is prioritized as:
				 * 1. If there is a labeled network then use the IP from that
				 * 2. If there is only a single network, besides the default ingress
				 *    network, then use that
				 * 3. If there is only a single network, than use that.
				 * 4. Else ignore task as we can't deterine which network to
				 *    use
				 */
				found := false
				count := len(networkLabels)
				for _, network := range task.NetworksAttachments {
					if count == 0 || labelMatch(network.Network.Spec.Labels, networkLabels) {
						ip, _, _ := net.ParseCIDR(network.Addresses[0])
						info.Nodes = append(info.Nodes, ip.String())
						found = true
						break
					}
				}
				if !found {
					log.Warnf("Unable to determine network (IP) information for task '%s'",
						task.ID)
				}
			}
		}
	}

	return &info, nil
}

func (c *SwarmClient) Close() error {
	return nil
}
