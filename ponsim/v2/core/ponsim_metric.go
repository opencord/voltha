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
package core

import (
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/protos/go/voltha"
	"github.com/sirupsen/logrus"
)

/*
metricCounter holds details for a specific metric
*/
type metricCounter struct {
	Name  string
	Value [2]int // [PON,NNI] values
	Min   int
	Max   int
}

/*
Create a new MetricCounter instance for TX packets
*/
func newTxMetricCounter(name txMetricCounterType, min int, max int) *metricCounter {
	return &metricCounter{Name: name.String(), Min: min, Max: max}
}

/*
Create a new MetricCounter instance for RX packets
*/
func newRxMetricCounter(name rxMetricCounterType, min int, max int) *metricCounter {
	return &metricCounter{Name: name.String(), Min: min, Max: max}
}

/*
Define TX constants
*/
type txMetricCounterType uint8

const (
	tx_64_pkts txMetricCounterType = iota
	tx_65_127_pkts
	tx_128_255_pkts
	tx_256_511_pkts
	tx_512_1023_pkts
	tx_1024_1518_pkts
	tx_1519_9k_pkts
)

/*
TX packet constants string equivalents
*/
var txMetricCounterEnum = []string{
	"tx_64_pkts",
	"tx_65_127_pkts",
	"tx_128_255_pkts",
	"tx_256_511_pkts",
	"tx_512_1023_pkts",
	"tx_1024_1518_pkts",
	"tx_1519_9k_pkts",
}

func (t txMetricCounterType) String() string {
	return txMetricCounterEnum[t]
}

/*
Define RX constants
*/
type rxMetricCounterType uint8

const (
	rx_64_pkts rxMetricCounterType = iota
	rx_65_127_pkts
	rx_128_255_pkts
	rx_256_511_pkts
	rx_512_1023_pkts
	rx_1024_1518_pkts
	rx_1519_9k_pkts
)

/*
RX packet constants string equivalents
*/
var rxMetricCounterEnum = []string{
	"rx_64_pkts",
	"rx_65_127_pkts",
	"rx_128_255_pkts",
	"rx_256_511_pkts",
	"rx_512_1023_pkts",
	"rx_1024_1518_pkts",
	"rx_1519_9k_pkts",
}

func (t rxMetricCounterType) String() string {
	return rxMetricCounterEnum[t]
}

/*

 */
type PonSimMetricCounter struct {
	Name       string
	Device_Type string
	TxCounters map[txMetricCounterType]*metricCounter
	RxCounters map[rxMetricCounterType]*metricCounter
}

/*
NewPonSimMetricCounter instantiates new metric counters for a PON device
*/
func NewPonSimMetricCounter(name string, device_type string) *PonSimMetricCounter {
	counter := &PonSimMetricCounter{Name: name, Device_Type: device_type}

	counter.TxCounters = map[txMetricCounterType]*metricCounter{
		tx_64_pkts:        newTxMetricCounter(tx_64_pkts, 1, 64),
		tx_65_127_pkts:    newTxMetricCounter(tx_65_127_pkts, 65, 127),
		tx_128_255_pkts:   newTxMetricCounter(tx_128_255_pkts, 128, 255),
		tx_256_511_pkts:   newTxMetricCounter(tx_256_511_pkts, 256, 511),
		tx_512_1023_pkts:  newTxMetricCounter(tx_512_1023_pkts, 512, 1023),
		tx_1024_1518_pkts: newTxMetricCounter(tx_1024_1518_pkts, 1024, 1518),
		tx_1519_9k_pkts:   newTxMetricCounter(tx_1519_9k_pkts, 1519, 9216),
	}
	counter.RxCounters = map[rxMetricCounterType]*metricCounter{
		rx_64_pkts:        newRxMetricCounter(rx_64_pkts, 1, 64),
		rx_65_127_pkts:    newRxMetricCounter(rx_65_127_pkts, 65, 127),
		rx_128_255_pkts:   newRxMetricCounter(rx_128_255_pkts, 128, 255),
		rx_256_511_pkts:   newRxMetricCounter(rx_256_511_pkts, 256, 511),
		rx_512_1023_pkts:  newRxMetricCounter(rx_512_1023_pkts, 512, 1023),
		rx_1024_1518_pkts: newRxMetricCounter(rx_1024_1518_pkts, 1024, 1518),
		rx_1519_9k_pkts:   newRxMetricCounter(rx_1519_9k_pkts, 1519, 9216),
	}

	return counter
}

/*
CountRxFrame increments the receive count for a specific packet size metric
*/
func (mc *PonSimMetricCounter) CountRxFrame(port int, size int) {
	for k, v := range mc.RxCounters {
		if size >= v.Min && size <= v.Max {
			mc.RxCounters[k].Value[port-1] += 1
		}
	}
}

/*
CountTxFrame increments the transmit count for a specific packet size metric
*/
func (mc *PonSimMetricCounter) CountTxFrame(port int, size int) {
	for k, v := range mc.TxCounters {
		if size >= v.Min && size <= v.Max {
			mc.TxCounters[k].Value[port-1] += 1
		}
	}
}

/*
LogCounts logs the current counts for all RX/TX packets
*/
func (mc *PonSimMetricCounter) LogCounts() {
	common.Logger().WithFields(logrus.Fields{
		"counters": mc.RxCounters,
	}).Info("RX Metrics")
	common.Logger().WithFields(logrus.Fields{
		"counters": mc.TxCounters,
	}).Info("TX Metrics")
}

/*
MakeProto collects all RX/TX metrics with which it constructs a GRPC proto metrics structure
*/
func (mc *PonSimMetricCounter) MakeProto() *voltha.PonSimMetrics {
	simMetrics := &voltha.PonSimMetrics{Device: mc.Name}
	ponMetrics := &voltha.PonSimPortMetrics{PortName: "pon"}
	portMetrics := &voltha.PonSimPortMetrics{}

	if (mc.Device_Type == "ONU") {
	    portMetrics.PortName = "uni"
	} else if (mc.Device_Type == "OLT") {
	    portMetrics.PortName = "nni"
	} else {
	    common.Logger().WithFields(logrus.Fields{
		"counters": mc.RxCounters,
	    }).Error("Unknown Device_Type in PonSimMetricCounter")
	    portMetrics.PortName = "unknown"
	}

	// Collect RX metrics
	for _, c := range mc.RxCounters {
		// PON values
		ponMetrics.Packets = append(
			ponMetrics.Packets,
			&voltha.PonSimPacketCounter{
				Name:  c.Name,
				Value: int64(c.Value[0]),
			},
		)
		// NNI/UNI values
		portMetrics.Packets = append(
			portMetrics.Packets,
			&voltha.PonSimPacketCounter{
				Name:  c.Name,
				Value: int64(c.Value[1]),
			},
		)
	}
	// Collect TX metrics
	for _, c := range mc.TxCounters {
		// PON values
		ponMetrics.Packets = append(
			ponMetrics.Packets,
			&voltha.PonSimPacketCounter{
				Name:  c.Name,
				Value: int64(c.Value[0]),
			},
		)
		// NNI/UNI values
		portMetrics.Packets = append(
			portMetrics.Packets,
			&voltha.PonSimPacketCounter{
				Name:  c.Name,
				Value: int64(c.Value[1]),
			},
		)
	}

	// Populate GRPC proto structure
	simMetrics.Metrics = append(simMetrics.Metrics, ponMetrics)
	simMetrics.Metrics = append(simMetrics.Metrics, portMetrics)

	return simMetrics
}
