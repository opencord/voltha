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
	"encoding/json"
	"github.com/Sirupsen/logrus"
)

/*
 * Structure used to capture the cluster configuraiton for ONOS and
 * generate the appropriate JSON
 */

// ClusterNode ONOS node information
type ClusterNode struct {
	ID   string `json:"id,omitempty"`
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

// ClusterPartition ONOS partition record
type ClusterPartition struct {
	ID      int      `json:"id,omitempty"`
	Members []string `json:"members,omitempty"`
}

// ClusterConfig ONOS cluster configuration
type ClusterConfig struct {
	Name       string             `json:"name,omitempty"`
	Nodes      []ClusterNode      `json:"nodes,omitempty"`
	Partitions []ClusterPartition `json:"partitions,omitempty"`
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

//
func GenerateConfig(info *ClusterInfo, update chan []byte) {
	if info == nil || info.Expected < 1 {
		log.Debugf("Expected instance count, %d, less than cluster minimum, generating empty config",
			info.Expected)
		update <- make([]byte, 0)
		return
	} else if info.Expected != uint64(len(info.Nodes)) {
		// If the expected and actual node count differ then don't update
		// config, a node might come back ater all
		log.Debugf("Expected instances, %d, differs from actual, %d, dropping",
			info.Expected, len(info.Nodes))
		return
	}

	// Verify connectivity to nodes on port 9876
	if err := VerifyNodes(info.Nodes, 9876); err != nil {
		// Not able to verify connection to ONOS cluster instance
		// so do not generate cluster meta data
		log.Debugf("Unable to verify connection to all nodes : %s, configuration not generated",
			err.Error())
		return
	}

	next := ClusterConfig{
		Name: "default",
	}
	next.Nodes = make([]ClusterNode, len(info.Nodes))
	for idx, node := range info.Nodes {
		next.Nodes[idx].ID = node
		next.Nodes[idx].IP = node
		next.Nodes[idx].Port = 9876
	}

	// Select a partition count that make "sense" depending on number
	// of nodes
	count := 1
	if len(info.Nodes) >= 5 {
		count = 5
	} else if len(info.Nodes) >= 3 {
		count = 3
	}
	next.Partitions = make([]ClusterPartition, count)

	log.Debugf("Generating config for %d nodes, with %d partitions",
		len(info.Nodes), count)
	start := 0
	perPart := minInt(len(info.Nodes), 3)
	for idx := 0; idx < count; idx += 1 {
		next.Partitions[idx].ID = idx + 1
		next.Partitions[idx].Members = make([]string, perPart)
		for midx := 0; midx < perPart; midx += 1 {
			key := (start + midx) % len(info.Nodes)
			next.Partitions[idx].Members[midx] = info.Nodes[key]
		}
		start += 1
	}

	data, err := json.Marshal(&next)
	if err != nil {
		log.Errorf("Unable to marshal cluster configuration : %s", err.Error())
	} else {
		if log.Level == logrus.DebugLevel {
			ppData, err := json.MarshalIndent(&next, "CONFIG: ", "  ")
			if err != nil {
				log.Warnf("Unable to marshal cluster configuration, for debug : %s", err.Error())
			} else {
				log.Debug(string(ppData))
			}
		}
		update <- data
	}
}
