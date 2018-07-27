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
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/gopacket"
	"github.com/google/uuid"
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/protos/go/ponsim"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// TODO: Cleanup GRPC security config
// TODO: Pass-in the certificate information as a structure parameter

/*
PonSimOnuDevice is the structure responsible for the handling of an ONU device
*/
type PonSimOnuDevice struct {
	PonSimDevice

	ParentAddress string
	ParentPort    int32
	AssignedPort  int32
	SerialNumber  string
	Conn          *grpc.ClientConn

	oltClient ponsim.PonSimCommonClient
	stream    ponsim.PonSimCommon_ProcessDataClient
	monitor   chan PonSimDeviceState
	state     PonSimDeviceState
}

/*
NewPonSimOnuDevice instantiates a new ONU device structure
*/
func NewPonSimOnuDevice(device PonSimDevice) *PonSimOnuDevice {
	onu := &PonSimOnuDevice{PonSimDevice: device}

	return onu
}

/*
forwardToOLT defines a INGRESS function to forward a packet to the parent OLT
*/
func (o *PonSimOnuDevice) forwardToOLT() func(int, gopacket.Packet) {
	return func(port int, frame gopacket.Packet) {
		ipAddress := common.GetInterfaceIP(o.InternalIf)
		incoming := &ponsim.IncomingData{
			Id:      "INGRESS.ONU." + ipAddress,
			Address: ipAddress,
			Port:    int32(port),
			Payload: frame.Data(),
		}
		common.Logger().WithFields(logrus.Fields{
			"device":    o,
			"port":      port,
			"frame":     frame,
			"frameDump": frame.Dump(),
			"incoming":  incoming,
		}).Debug("Forwarding to OLT")

		// Forward packet to OLT
		if err := o.stream.Send(incoming); err != nil {
			common.Logger().WithFields(logrus.Fields{
				"device":    o,
				"port":      port,
				"frameDump": frame.Dump(),
				"incoming":  incoming,
			}).Fatal("A problem occurred while forwarding to OLT")
		}
	}
}

/*
forwardToWAN defines a EGRESS function to forward a packet to the world
*/
func (o *PonSimOnuDevice) forwardToWAN() func(int, gopacket.Packet) {
	return func(port int, frame gopacket.Packet) {
		var err error
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"port":   port,
			"frame":  frame,
		}).Debug("Forwarding packet to world")
		if err = o.ingressHandler.WritePacketData(frame.Data()); err != nil {
			common.Logger().WithFields(logrus.Fields{
				"device": o,
				"port":   port,
				"frame":  frame,
			}).Fatal("Problem while forwarding packet to world")
		} else {
			common.Logger().WithFields(logrus.Fields{
				"device": o,
				"port":   port,
				"frame":  frame,
			}).Debug("Forwarded packet to world")
		}
	}
}

/*
Start performs setup operations for an ONU device
*/
func (o *PonSimOnuDevice) Start(ctx context.Context) {
	// Initialize the parent
	o.PonSimDevice.Start(ctx)

	// Setup flow behaviours
	// ONU -> OLT
	o.AddLink(1, 0, o.forwardToOLT())
	// ONU -> World
	o.AddLink(2, 0, o.forwardToWAN())

	go o.MonitorConnection(ctx)
}

/*
Stop performs cleanup operations for an ONU device
*/
func (o *PonSimOnuDevice) Stop(ctx context.Context) {
	common.Logger().WithFields(logrus.Fields{
		"device": o,
	}).Debug("Stopping ONU")

	o.RemoveLink(1, 0)
	o.RemoveLink(2, 0)

	o.PonSimDevice.Stop(ctx)
}

/*
Listen waits for incoming INGRESS data on the external interface
*/
func (o *PonSimOnuDevice) Listen(ctx context.Context) {
	var reply *empty.Empty
	var err error

	if o.oltClient = ponsim.NewPonSimCommonClient(o.Conn); o.oltClient == nil {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
		}).Fatal("Problem establishing client connection to OLT")
		panic("Problem establishing client connection to OLT")
	}

	// Establish GRPC connection with OLT
	if o.stream, err = o.oltClient.ProcessData(ctx); err != nil {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"error":  err.Error(),
		}).Fatal("Problem establishing stream")
		panic(err)
	}

	defer o.ingressHandler.Close()
	packetSource := gopacket.NewPacketSource(o.ingressHandler, o.ingressHandler.LinkType())
	common.Logger().WithFields(logrus.Fields{
		"device":    o,
		"interface": o.ExternalIf,
	}).Debug("Listening to incoming ONU data")

	for packet := range packetSource.Packets() {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"packet": packet,
		}).Debug("Received INGRESS packet")

		o.Forward(ctx, 2, packet)
	}

	common.Logger().WithFields(logrus.Fields{
		"device": o,
	}).Debug("No more packets to process")

	if reply, err = o.stream.CloseAndRecv(); err != nil {
		common.Logger().Fatal("A problem occurred while closing Ingress stream", err.Error())
	} else {
		common.Logger().Info("Ingress stream closed", reply)
	}
}

/*
Register sends a registration request to the remote OLT
*/
func (o *PonSimOnuDevice) Register(ctx context.Context) error {
	var err error
	var rreq *ponsim.RegistrationRequest
	var rrep *ponsim.RegistrationReply
	var client ponsim.PonSimOltClient

	if o.Conn != nil {
		if client = ponsim.NewPonSimOltClient(o.Conn); client != nil {
			rreq = &ponsim.RegistrationRequest{
				Id:      uuid.New().String(),
				Address: common.GetInterfaceIP(o.InternalIf),
				Port:    o.Port,
				SerialNumber: o.SerialNumber,
			}
			common.Logger().Printf("Request details %+v\n", rreq)

			// TODO: Loop registration until an OLT becomes available??

			rrep, err = client.Register(ctx, rreq)
			if err != nil {
				common.Logger().Printf("Problem with registration", err.Error())
			} else {
				// Save OLT address details
				o.ParentAddress = rrep.GetParentAddress()
				o.ParentPort = rrep.GetParentPort()
				o.AssignedPort = rrep.GetAssignedPort()

				common.Logger().Printf("Registration details - %+v\n", rrep)

				o.monitor <- REGISTERED_WITH_OLT
			}

		} else {
			common.Logger().Info("Client is NIL")
		}
	}

	return err
}

/*
MonitorConnection verifies the communication with the OLT
*/
func (o *PonSimOnuDevice) MonitorConnection(ctx context.Context) {
	for {
		if o.state == DISCONNECTED_FROM_PON {
			// Establish communication with OLT
			o.Connect(ctx)
		}

		if o.state == CONNECTED_TO_PON {
			// Just stay idle while the ONU-OLT connection is up
			o.Conn.WaitForStateChange(ctx, o.Conn.GetState())

			// The ONU-OLT connection was lost... need to cleanup
			o.Disconnect(ctx)
		}

		time.Sleep(1 * time.Second)
	}
}

/*
Connect sets up communication and monitoring with remote OLT
*/
func (o *PonSimOnuDevice) Connect(ctx context.Context) {
	o.monitor = make(chan PonSimDeviceState, 1)

	// Define a waitgroup to block the current routine until
	// a CONNECTED state is reached
	wg := sync.WaitGroup{}
	wg.Add(1)

	go o.MonitorState(ctx, &wg)

	o.ConnectToRemoteOlt()

	// Wait until we establish a connection to the remote PON
	wg.Wait()
}

/*
Disconnect tears down communication and monitoring with remote OLT
*/
func (o *PonSimOnuDevice) Disconnect(ctx context.Context) {
	if o.egressHandler != nil {
		o.egressHandler.Close()
		o.egressHandler = nil
	}

	if o.Conn != nil {
		o.Conn.Close()
		o.Conn = nil
	}

	if o.monitor != nil {
		close(o.monitor)
		o.monitor = nil
		o.state = DISCONNECTED_FROM_PON
	}
}

/*
MonitorState follows the progress of the OLT connection
*/
func (o *PonSimOnuDevice) MonitorState(ctx context.Context, wg *sync.WaitGroup) {
	// Start a concurrent routine to handle ONU state changes
	var ok bool
	for {
		select {
		case o.state, ok = <-o.monitor:
			if ok {
				common.Logger().WithFields(logrus.Fields{
					"device": o,
					"state":  o.state,
				}).Info("Received monitoring state")

				switch o.state {
				case CONNECTED_TO_PON:
					// We have successfully connected to the OLT
					// proceed with registration
					wg.Done()

					if err := o.Register(ctx); err != nil {
						o.Disconnect(ctx)
					}

				case DISCONNECTED_FROM_PON:
					// Connection to remote OLT was lost... exit
					common.Logger().WithFields(logrus.Fields{
						"device": o,
					}).Warn("Exiting due to disconnection")
					return

				case REGISTERED_WITH_OLT:
					// Start listening on network interfaces
					o.connectNetworkInterfaces()
					o.monitor <- CONNECTED_IO_INTERFACE

				case CONNECTED_IO_INTERFACE:
					// Start listening on local interfaces
					go o.Listen(ctx)
				}
			} else {
				common.Logger().WithFields(logrus.Fields{
					"device": o,
				}).Warn("Monitoring channel has closed")
				return
			}
		case <-ctx.Done():
			common.Logger().WithFields(logrus.Fields{
				"device": o,
			}).Warn("Received a cancellation notification")

			return
		}
	}
}

/*
ConnectToRemoteOlt establishes GRPC communication with the remote OLT
*/
func (o *PonSimOnuDevice) ConnectToRemoteOlt() {
	common.Logger().WithFields(logrus.Fields{
		"device": o,
	}).Debug("Connecting to remote device")

	var err error

	host := strings.Join([]string{
		o.ParentAddress,
		strconv.Itoa(int(o.ParentPort)),
	}, ":")

	if o.Conn, err = grpc.DialContext(
		context.Background(), host, grpc.WithInsecure(), grpc.WithBlock(),
	); err != nil {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"error":  err.Error(),
		}).Error("Problem establishing connection")
	} else {
		// We are now connected
		// time to move on
		common.Logger().WithFields(logrus.Fields{
			"device": o,
		}).Info("Connected to OLT")
	}

	o.monitor <- CONNECTED_TO_PON
}
