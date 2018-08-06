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
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/gopacket"
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/protos/go/openflow_13"
	"github.com/opencord/voltha/protos/go/ponsim"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// TODO: Pass-in the certificate information as a structure parameter

/*
PonSimOltDevice is the structure responsible for the handling of an OLT device
*/
type PonSimOltDevice struct {
	PonSimDevice  `json:pon_device`
	VCoreEndpoint string                  `json:vcore_ep`
	MaxOnuCount   int                     `json:max_onu`
	Onus          map[int32]*OnuRegistree `json:onu_registrees`
	outgoing      chan []byte

	counterLoop *common.IntervalHandler
	alarmLoop   *common.IntervalHandler
}

/*

 */
type OnuRegistree struct {
	Device *PonSimOnuDevice                      `json:onu_device`
	Conn   *grpc.ClientConn                      `json:grpc_conn`
	Client ponsim.PonSimCommonClient             `json:client`
	Stream ponsim.PonSimCommon_ProcessDataClient `json:stream`
}

const (
	BASE_PORT_NUMBER = 128
)

/*
NewPonSimOltDevice instantiates a new OLT device structure
*/
func NewPonSimOltDevice(device PonSimDevice) *PonSimOltDevice {
	olt := &PonSimOltDevice{PonSimDevice: device}
	return olt
}

/*
forwardToONU defines a EGRESS function to forward a packet to a specific ONU
*/
func (o *PonSimOltDevice) forwardToONU(onuPort int32) func(int, gopacket.Packet) {
	return func(port int, frame gopacket.Packet) {
		ipAddress := common.GetInterfaceIP(o.ExternalIf)
		incoming := &ponsim.IncomingData{
			Id:      "EGRESS.OLT." + ipAddress,
			Address: ipAddress,
			Port:    int32(port),
			Payload: frame.Data(),
		}
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"port":   port,
			"frame":  frame,
		}).Debug("Forwarding to ONU")

		// Forward packet to ONU
		if err := o.GetOnu(onuPort).Stream.Send(incoming); err != nil {
			common.Logger().WithFields(logrus.Fields{
				"device":    o,
				"frameDump": frame.Dump(),
				"incoming":  incoming,
				"error":     err.Error(),
			}).Error("A problem occurred while forwarding to ONU")
		}

	}
}

/*
forwardToLAN defines an INGRESS function to forward a packet to VOLTHA
*/
func (o *PonSimOltDevice) forwardToLAN() func(int, gopacket.Packet) {
	return func(port int, frame gopacket.Packet) {
		common.Logger().WithFields(logrus.Fields{
			"frame": frame.Dump(),
		}).Info("Sending packet")

		select {
		case o.outgoing <- frame.Data():
			common.Logger().WithFields(logrus.Fields{
				"frame": frame.Dump(),
			}).Info("Sent packet")
		default:
			common.Logger().WithFields(logrus.Fields{
				"frame": frame.Dump(),
			}).Warn("Unable to send packet")
		}
	}
}

/*
forwardToNNI defines function to forward a packet to the NNI interface
*/
func (o *PonSimOltDevice) forwardToNNI() func(int, gopacket.Packet) {
	return func(port int, frame gopacket.Packet) {
		var err error
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"port":   port,
			"frame":  frame,
		}).Debug("Forwarding packet to NNI")
		if err = o.egressHandler.WritePacketData(frame.Data()); err != nil {
			common.Logger().WithFields(logrus.Fields{
				"device": o,
				"port":   port,
				"frame":  frame,
			}).Fatal("Problem while forwarding packet to NNI")
		} else {
			common.Logger().WithFields(logrus.Fields{
				"device": o,
				"port":   port,
				"frame":  frame,
			}).Debug("Forwarded packet to NNI")
		}
	}
}

/*
Start performs setup operations for an OLT device
*/
func (o *PonSimOltDevice) Start(ctx context.Context) {
	common.Logger().Info("Starting OLT device...")
	o.PonSimDevice.Start(ctx)

	// Open network interfaces for listening
	o.connectNetworkInterfaces()

	o.outgoing = make(chan []byte, 1)

	// Add INGRESS operation
	o.AddLink(int(openflow_13.OfpPortNo_OFPP_CONTROLLER), 0, o.forwardToLAN())

	// Add Data-Plane Forwarding operation
	o.AddLink(2, 0, o.forwardToNNI())

	// Start PM counter logging
	o.counterLoop = common.NewIntervalHandler(90, o.Counter.LogCounts)
	o.counterLoop.Start()

	// Start alarm simulation
	if o.AlarmsOn {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
		}).Debug("Starting alarm simulation")

		alarms := NewPonSimAlarm(o.InternalIf, o.VCoreEndpoint, o.forwardToLAN())
		o.alarmLoop = common.NewIntervalHandler(o.AlarmsFreq, alarms.GenerateAlarm)
		o.alarmLoop.Start()
	}
}

/*
Stop performs cleanup operations for an OLT device
*/
func (o *PonSimOltDevice) Stop(ctx context.Context) {
	common.Logger().Info("Stopping OLT device...")

	// Stop PM counters loop
	o.counterLoop.Stop()
	o.counterLoop = nil

	// Stop alarm simulation
	if o.AlarmsOn {
		o.alarmLoop.Stop()
	}
	o.alarmLoop = nil

	o.ingressHandler.Close()
	o.egressHandler.Close()

	o.PonSimDevice.Stop(ctx)
}

/*
ConnectToRemoteOnu establishes communication to a remote ONU device
*/
func (o *PonSimOltDevice) ConnectToRemoteOnu(onu *OnuRegistree) error {
	var err error

	host := strings.Join([]string{
		onu.Device.Address,
		strconv.Itoa(int(onu.Device.Port)),
	}, ":")

	common.Logger().WithFields(logrus.Fields{
		"device": o,
		"host":   host,
	}).Debug("Formatting host address")

	// GRPC communication needs to be secured
	if onu.Conn, err = grpc.DialContext(
		context.Background(),
		host,
		grpc.WithInsecure(),
	); err != nil {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"error":  err.Error(),
		}).Error("Problem with client connection")
	}

	return err
}

/*
Listen waits for incoming EGRESS data on the internal interface
*/
func (o *PonSimOltDevice) Listen(ctx context.Context, port int32) {
	var reply *empty.Empty
	var err error

	// Establish a GRPC connection with the ONU
	onu := o.GetOnu(port)

	common.Logger().WithFields(logrus.Fields{
		"onu": onu,
	}).Debug("Connecting to remote ONU")

	if onu.Client = ponsim.NewPonSimCommonClient(onu.Conn); onu.Client == nil {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
		}).Error("Problem establishing client connection to ONU")
		o.RemoveOnu(ctx, port)
		return
	}

	// Prepare stream to ONU to forward incoming data as needed
	if onu.Stream, err = onu.Client.ProcessData(ctx); err != nil {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
		}).Error("Problem establishing stream to ONU")
		o.RemoveOnu(ctx, port)
		return
	}

	defer o.egressHandler.Close()
	packetSource := gopacket.NewPacketSource(o.egressHandler, o.egressHandler.LinkType())
	common.Logger().WithFields(logrus.Fields{
		"device":    o,
		"interface": o.InternalIf,
	}).Debug("Listening to incoming EGRESS data")

	// Wait for incoming EGRESS data
	for packet := range packetSource.Packets() {
		if dot1q := common.GetDot1QLayer(packet); dot1q != nil {
			common.Logger().WithFields(logrus.Fields{
				"device": o,
				"packet": packet,
			}).Debug("Received EGRESS packet")

			o.Forward(ctx, 2, packet)
		}
	}

	common.Logger().WithFields(logrus.Fields{
		"device": o,
	}).Debug("No more packets to process")

	if reply, err = onu.Stream.CloseAndRecv(); err != nil {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"error":  err.Error(),
		}).Error("A problem occurred while closing client stream")
	} else {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"reply":  reply,
		}).Warn("Client stream closed")
	}
}

/*
GetOnus returns the list of registered ONU devices
*/
func (o *PonSimOltDevice) GetOnus() map[int32]*OnuRegistree {
	if o.Onus == nil {
		o.Onus = make(map[int32]*OnuRegistree)
	}

	return o.Onus
}

/*
GetOnu return a specific registered ONU
*/
func (o *PonSimOltDevice) GetOnu(index int32) *OnuRegistree {
	var onu *OnuRegistree
	var ok bool

	if onu, ok = (o.GetOnus())[index]; ok {
		return onu
	}

	return nil
}

func (o *PonSimOltDevice) GetOutgoing() chan []byte {
	return o.outgoing
}

/*
nextAvailablePort returns a port that is not already used by a registered ONU
*/
func (o *PonSimOltDevice) nextAvailablePort() int32 {
	var port int32 = BASE_PORT_NUMBER

	if len(o.GetOnus()) < o.MaxOnuCount {
		for {
			if o.GetOnu(port) != nil {
				// port is already used
				port += 1
			} else {
				// port is available... use it
				return port
			}
		}
	} else {
		// OLT has reached its max number of ONUs
		return -1
	}
}

/*
AddOnu registers an ONU device and sets up all required monitoring and connections
*/
func (o *PonSimOltDevice) AddOnu(onu *PonSimOnuDevice) (int32, error) {
	var portNum int32
	ctx := context.Background()

	if portNum = o.nextAvailablePort(); portNum != -1 {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"port":   portNum,
			"onu":    onu,
		}).Info("Adding ONU")

		registree := &OnuRegistree{Device: onu}

		// Setup GRPC communication and check if it succeeded
		if err := o.ConnectToRemoteOnu(registree); err == nil {
			o.GetOnus()[portNum] = registree

			o.AddLink(1, int(portNum), o.forwardToONU(portNum))
			common.Logger().WithFields(logrus.Fields{
				"port": portNum,
				"onu":  onu,
			}).Info("Connected ONU")
			go o.MonitorOnu(ctx, portNum)
			go o.Listen(ctx, portNum)
		}

	} else {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
		}).Warn("ONU Map is full")
	}

	return int32(portNum), nil
}

/*
RemoveOnu removes the reference to a registered ONU
*/
func (o *PonSimOltDevice) RemoveOnu(ctx context.Context, onuIndex int32) error {
	onu := o.GetOnu(onuIndex)
	if err := onu.Conn.Close(); err != nil {
		common.Logger().WithFields(logrus.Fields{
			"device":   o,
			"onu":      onu.Device,
			"onuIndex": onuIndex,
		}).Error("Problem closing connection to ONU")
	}

	common.Logger().WithFields(logrus.Fields{
		"device":   o,
		"onu":      onu,
		"onuIndex": onuIndex,
	}).Info("Removing ONU")

	delete(o.Onus, onuIndex)

	// Remove link entries for this ONU
	o.RemoveLink(1, int(onuIndex))

	return nil
}

/*
MonitorOnu verifies the connection status of a specific ONU and cleans up as necessary
*/
func (o *PonSimOltDevice) MonitorOnu(ctx context.Context, onuIndex int32) {
	for {
		if o.GetOnu(onuIndex) != nil {
			if conn := o.GetOnu(onuIndex).Conn; conn.GetState() == connectivity.Ready {
				// Wait for any change to occur
				conn.WaitForStateChange(ctx, conn.GetState())
				// We lost communication with the ONU ... remove it
				o.RemoveOnu(ctx, onuIndex)
				return
			}
			common.Logger().WithFields(logrus.Fields{
				"device":   o,
				"ctx":      ctx,
				"onuIndex": onuIndex,
			}).Debug("ONU is not ready")
			time.Sleep(1 * time.Second)
		} else {
			return
		}
	}
}
