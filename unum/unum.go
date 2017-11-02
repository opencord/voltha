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
	"os"
	"text/tabwriter"
	"time"

	"github.com/Sirupsen/logrus"
	_ "github.com/dimiro1/banner/autoload"
	"github.com/kelseyhightower/envconfig"
)

const (
	// configTemplate used to display the configuration values for informational/debbug purposes
	configTemplate = `This service is configured by the environment. The following
are the configuration values:
    KEY	VALUE	DESCRIPTION
    {{range .}}{{usage_key .}}	{{.Field}}	{{usage_description .}}
    {{end}}`
)

// configSpec configuration options for the cluster manager, see envconfig project
type configSpec struct {
	Orchestrator string            `envconfig:"ORCHESTRATOR" desc:"specifies how to connect to the container orchestration system" default:"swarm://"`
	Labels       map[string]string `envconfig:"LABELS" desc:"labels to match service" default:"org.onosproject.cluster:true"`
	Network      map[string]string `envconfig:"NETWORK" desc:"labels to match against connected networks to determine IP selection for ONOS instance" default:"org.onosproject.cluster:true"`
	Listen       string            `envconfig:"LISTEN" desc:"interface on which to listen for cluster configuration requests" default:"0.0.0.0:5411"`
	Period       time.Duration     `envconfig:"PERIOD" desc:"how often should the container orchestrator be queried" default:"1s"`
	LogLevel     string            `envconfig:"LOG_LEVEL" desc:"detail level for logging" default:"warning"`
	LogFormat    string            `envconfig:"LOG_FORMAT" desc:"log output format, text or json" default:"text"`
}

var log = logrus.New()

// myStruct testing
type myStruct struct{}

// labelMatch returns true if the labels and values specified in needs are in the label map of has
func labelMatch(has map[string]string, needs map[string]string) bool {
	for label, val1 := range needs {
		if val2, ok := has[label]; !ok || val2 != val1 {
			return false
		}
	}
	return true
}

func main() {

	// Load configuration values and output for information/debug purposes
	var config configSpec
	envconfig.Process("", &config)
	tabs := tabwriter.NewWriter(os.Stdout, 4, 4, 4, ' ', 0)
	err := envconfig.Usagef("", &config, tabs, configTemplate)
	if err != nil {
		panic(err)
	}
	tabs.Flush()
	fmt.Println()

	// Establish logging configuraton
	switch config.LogFormat {
	case "json":
		log.Formatter = &logrus.JSONFormatter{}
	default:
		log.Formatter = &logrus.TextFormatter{
			FullTimestamp: true,
			ForceColors:   true,
		}
	}
	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		log.Errorf("Invalid error level specified: '%s', defaulting to WARN level", config.LogLevel)
		level = logrus.WarnLevel
	}
	log.Level = level

	log.Info("Starting ONOS Cluster Manager (unum)")

	// Get adapter to orchestrator
	url, err := url.Parse(config.Orchestrator)
	if err != nil {
		log.Errorf("Unable to parse specified orchestrator URL, '%s' : %s", config.Orchestrator, err.Error())
		panic(err)
	}

	// Create client for container orchestratory based on URL
	orch, err := NewOrchestrationClient(url)
	if err != nil {
		log.Errorf("Unable to establish connection to container orchestrator, '%s' : %s",
			url, err.Error())
		panic(err)
	}

	// Get cluster information and build initial cluster configuration
	info, err := orch.GetInfo(config.Labels, config.Network)
	if err != nil {
		log.Warnf("Unable to query cluster information from container orchestratory : %s",
			err.Error())
	}

	listener := &Listener{
		ListenOn: config.Listen,
	}
	listener.Init()

	// Set the initial cluster configuration
	if err == nil {
		GenerateConfig(info, listener.Update)
	}

	// Set up the REST listener for the ONOS cluster configuraiton server
	go listener.ListenAndServe()

	// Loop forever, quering for cluster information and updating the cluster configuration
	// when needed
	for {
		info, err := orch.GetInfo(config.Labels, config.Network)
		if err != nil {
			log.Warnf("Unable to query cluster information from container orchestrator : %s",
				err.Error())
		} else {

			log.Debugf("EXPECTED: %d, HAVE: %d", info.Expected, len(info.Nodes))
			if info.Expected == uint64(len(info.Nodes)) || info.Expected == 0 {
				GenerateConfig(info, listener.Update)
			}
		}

		// configurable pause
		time.Sleep(config.Period)
	}
}
