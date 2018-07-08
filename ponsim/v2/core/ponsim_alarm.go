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
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/protos/go/voltha"
	"github.com/sirupsen/logrus"
	"math/rand"
	"net"
	"time"
)

// TODO: user-defined values? min/max intervals, vlan?

const (
	minInterval = 20
	maxInterval = 60
	vlandId     = 4000
	localhost   = "127.0.0.1"
	ttl         = 64
	ipVersion   = 4
)

type Alarm struct {
	Severity    int    `json:"severity"`
	Type        int    `json:"type"`
	Category    int    `json:"category"`
	State       int    `json:"state"`
	TimeStamp   int    `json:"ts"`
	Description string `json:"description"`
}

/*
PonSimAlarm is the structure responsible for the handling of alarms
*/
type PonSimAlarm struct {
	forwardFunction func(int, gopacket.Packet)
	dstInterface    string
	dstEndpoint     string
}

/*
NewPonSimAlarm instantiates a new alarm handling structure
*/
func NewPonSimAlarm(dstInterface string, dstEndpoint string, function func(int, gopacket.Packet)) *PonSimAlarm {
	psa := &PonSimAlarm{dstInterface: dstInterface, dstEndpoint: dstEndpoint, forwardFunction: function}
	return psa
}

/*
prepareAlarm constructs an alarm object with random field values.
*/
func (a *PonSimAlarm) prepareAlarm() *Alarm {
	alarm_severity := rand.Intn(len(voltha.AlarmEventSeverity_AlarmEventSeverity_value))
	alarm_type := rand.Intn(len(voltha.AlarmEventType_AlarmEventType_value))
	alarm_category := rand.Intn(len(voltha.AlarmEventCategory_AlarmEventCategory_value))
	alarm_state := int(voltha.AlarmEventState_RAISED)
	alarm_ts := time.Now().UTC().Second()
	alarm_description := fmt.Sprintf("%s.%s alarm",
		voltha.AlarmEventType_AlarmEventType_name[int32(alarm_type)],
		voltha.AlarmEventCategory_AlarmEventCategory_name[int32(alarm_category)],
	)

	alarm := &Alarm{
		Severity:    alarm_severity,
		Type:        alarm_type,
		Category:    alarm_category,
		State:       alarm_state,
		TimeStamp:   alarm_ts,
		Description: alarm_description,
	}

	return alarm
}

/*
sendAlarm constructs and forwards the alarm to the network
*/
func (a *PonSimAlarm) sendAlarm(alarm *Alarm) {
	// Ethernet layer is configured as a broadcast packet
	ethLayer := &layers.Ethernet{
		SrcMAC:       common.GetMacAddress(a.dstInterface),
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeDot1Q,
	}

	// Need to encapsulate in VLAN so that voltha captures the packet
	dot1qLayer := &layers.Dot1Q{
		Type:           layers.EthernetTypeIPv4,
		VLANIdentifier: vlandId,
	}

	common.Logger().WithFields(logrus.Fields{
		"Alarm": a,
		"srcIp": common.GetInterfaceIP(a.dstInterface),
		"dstIp": common.GetHostIP(a.dstEndpoint),
	}).Info("SRC/DST IP addresses")

	// IP layer needs the following attributes at a minimum in order to have
	// a properly formed packet
	ipLayer := &layers.IPv4{
		SrcIP: net.ParseIP(common.GetInterfaceIP(a.dstInterface)),
		DstIP: net.ParseIP(common.GetHostIP(a.dstEndpoint)),
		//SrcIP:    net.ParseIP(localhost),
		//DstIP:    net.ParseIP(localhost),
		Version:  ipVersion,
		TTL:      ttl,
		Protocol: layers.IPProtocolTCP,
	}

	// TCP layer does not require anything special
	// except than providing the IP layer so that the checksum can be
	// properly calculated
	tcpLayer := &layers.TCP{}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Convert the alarm to bytes to include it as the packet payload
	rawData, _ := json.Marshal(alarm)

	// Construct the packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options,
		ethLayer,
		dot1qLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(rawData),
	)
	frame := gopacket.NewPacket(
		buffer.Bytes(),
		layers.LayerTypeEthernet,
		gopacket.Default,
	)

	// Forward the packetized alarm to the network
	a.forwardFunction(0, frame)

	common.Logger().WithFields(logrus.Fields{
		"Alarm": alarm,
		"Frame": frame.Dump(),
	}).Debug("Sent alarm")
}

/*
raiseAlarm submits an alarm object with a RAISED state
*/
func (a *PonSimAlarm) raiseAlarm(alarm *Alarm) {
	alarm.State = int(voltha.AlarmEventState_RAISED)
	a.sendAlarm(alarm)
}

/*
clearAlarm submits an alarm object with a CLEARED state
*/
func (a *PonSimAlarm) clearAlarm(alarm *Alarm) {
	alarm.State = int(voltha.AlarmEventState_CLEARED)
	a.sendAlarm(alarm)
}

/*
GenerateAlarm simulates RAISE and CLEAR alarm events with a random delay in between each state.
*/
func (a *PonSimAlarm) GenerateAlarm() {
	alarm := a.prepareAlarm()
	a.raiseAlarm(alarm)
	time.Sleep(time.Duration(rand.Intn(maxInterval-minInterval)+minInterval) * time.Second)
	a.clearAlarm(alarm)
}
