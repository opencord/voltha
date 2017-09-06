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
	"github.com/tatsushid/go-fastping"
	"net"
	"time"
)

// VerifyConnection verify the connection by attempt to connect to the host
func VerifyNodes(nodes []string, port int) error {

	var err error

	pinger := fastping.NewPinger()
	//pinger.Network("udp")
	pinger.MaxRTT, err = time.ParseDuration("1s")
	if err != nil {
		return err
	}

	count := len(nodes)
	pinger.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		count -= 1
	}
	for _, node := range nodes {
		pinger.AddIPAddr(&net.IPAddr{IP: net.ParseIP(node)})
	}
	if err := pinger.Run(); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("Unable to verify all nodes, %d unverified", count)
	}

	return nil
}
