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
package nbi

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/ponsim/v2/core"
	"github.com/opencord/voltha/protos/go/voltha"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type PonSimHandler struct {
	device core.PonSimInterface
}

/*
NewPonSimHandler instantiates a handler for a PonSim device
*/
func NewPonSimHandler(device core.PonSimInterface) *PonSimHandler {
	var handler *PonSimHandler
	handler = &PonSimHandler{device: device}
	return handler
}

/*
SendFrame handles and forwards EGRESS packets (i.e. VOLTHA to OLT)
*/
func (handler *PonSimHandler) SendFrame(ctx context.Context, data *voltha.PonSimFrame) (*empty.Empty, error) {
	frame := gopacket.NewPacket(data.Payload, layers.LayerTypeEthernet, gopacket.Default)

	common.Logger().WithFields(logrus.Fields{
		"handler": handler,
		"out_port": int(data.OutPort),
		"frame":   frame.Dump(),
	}).Info("Constructed frame")

	handler.device.SendOut(int(data.OutPort), frame)

	out := new(empty.Empty)
	return out, nil
}

/*
ReceiveFrames handles a stream of INGRESS packets (i.e. OLT to VOLTHA)
*/
func (handler *PonSimHandler) ReceiveFrames(empty *empty.Empty, stream voltha.PonSim_ReceiveFramesServer) error {
	common.Logger().WithFields(logrus.Fields{
		"handler": handler,
	}).Info("start-receiving-frames")

	if _, ok := (handler.device).(*core.PonSimOltDevice); ok {
		var data []byte
		var ok bool

		common.Logger().WithFields(logrus.Fields{
			"handler": handler,
			"device":  (handler.device).(*core.PonSimOltDevice),
		}).Info("receiving-frames-from-olt-device")

		for {
			select {
			case data, ok = <-(handler.device).(*core.PonSimOltDevice).GetOutgoing():
				if ok {
					frame := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
					common.Logger().WithFields(logrus.Fields{
						"handler": handler,
						"frame":   frame,
					}).Info("Received incoming data")

					frameBytes := &voltha.PonSimFrame{Id: handler.device.GetAddress(), Payload: data}
					if err := stream.Send(frameBytes); err != nil {
						common.Logger().WithFields(logrus.Fields{
							"handler": handler,
							"frame":   frame,
							"error":   err,
						}).Error("Failed to send incoming data")
						return err
					}
					common.Logger().WithFields(logrus.Fields{
						"handler": handler,
						"frame":   frame,
					}).Info("Sent incoming data")

				} else {
					return errors.New("incoming data channel has closed")
				}
			}
		}

	} else {
		common.Logger().WithFields(logrus.Fields{
			"handler": handler,
		}).Error("Not handling an OLT device")
	}

	return nil
}

/*
GetDeviceInfo returns information of a PonSim device (OLT or ONU)
*/
func (handler *PonSimHandler) GetDeviceInfo(
	ctx context.Context,
	empty *empty.Empty,
) (*voltha.PonSimDeviceInfo, error) {
	common.Logger().WithFields(logrus.Fields{
		"handler": handler,
	}).Info("Getting device information")

	out := &voltha.PonSimDeviceInfo{}

	// Check which device type we're currently handling
	if _, ok := (handler.device).(*core.PonSimOltDevice); ok {
		common.Logger().WithFields(logrus.Fields{
			"handler": handler,
		}).Debug("Handling OLT device")
		onus := (handler.device).(*core.PonSimOltDevice).GetOnus()
		for k := range onus {
			out.Onus = append(
				out.Onus,
				&voltha.PonSimOnuDeviceInfo {
					UniPort: k,
					SerialNumber: onus[k].Device.SerialNumber,
				},
			)
		}
		out.NniPort = 2
	} else {
		common.Logger().WithFields(logrus.Fields{
			"handler": handler,
		}).Debug("Handling ONU/OTHER device")
	}

	common.Logger().WithFields(logrus.Fields{
		"handler": handler,
		"result":  out,
	}).Info("Device information")

	return out, nil
}

/*
UpdateFlowTable populates and cleans up the flows for a PonSim device
*/
func (handler *PonSimHandler) UpdateFlowTable(
	ctx context.Context,
	table *voltha.FlowTable,
) (*empty.Empty, error) {
	common.Logger().WithFields(logrus.Fields{
		"handler": handler,
		"table":   table,
	}).Info("Updating flows")

	if _, ok := (handler.device).(*core.PonSimOltDevice); ok {
		if table.Port == 0 {
			common.Logger().WithFields(logrus.Fields{
				"handler": handler,
				"port":    table.Port,
			}).Debug("Updating OLT flows")

			if err := (handler.device).(*core.PonSimOltDevice).InstallFlows(ctx, table.Flows); err != nil {
				common.Logger().WithFields(logrus.Fields{
					"handler": handler,
					"error":   err.Error(),
					"flows":   table.Flows,
				}).Error("Problem updating flows on OLT")
			} else {
				common.Logger().WithFields(logrus.Fields{
					"handler": handler,
				}).Debug("Updated OLT flows")
			}

		} else {
			common.Logger().WithFields(logrus.Fields{
				"handler": handler,
				"port":    table.Port,
			}).Debug("Updating ONU flows")

			if child, ok := (handler.device).(*core.PonSimOltDevice).GetOnus()[table.Port]; ok {

				host := strings.Join([]string{
					child.Device.Address,
					strconv.Itoa(int(child.Device.Port)),
				}, ":")

				conn, err := grpc.Dial(
					host,
					grpc.WithInsecure(),
				)
				if err != nil {
					common.Logger().WithFields(logrus.Fields{
						"handler": handler,
						"error":   err.Error(),
					}).Error("GRPC Connection problem")
				}
				defer conn.Close()
				client := voltha.NewPonSimClient(conn)

				if _, err = client.UpdateFlowTable(ctx, table); err != nil {
					common.Logger().WithFields(logrus.Fields{
						"handler": handler,
						"host":    host,
						"error":   err.Error(),
					}).Error("Problem forwarding update request to ONU")
				}
			} else {
				common.Logger().WithFields(logrus.Fields{
					"handler": handler,
					"port":    table.Port,
				}).Warn("Unable to find ONU")
			}

		}
	} else if _, ok := (handler.device).(*core.PonSimOnuDevice); ok {
		if err := (handler.device).(*core.PonSimOnuDevice).InstallFlows(ctx, table.Flows); err != nil {
			common.Logger().WithFields(logrus.Fields{
				"handler": handler,
				"error":   err.Error(),
				"flows":   table.Flows,
			}).Error("Problem updating flows on ONU")
		} else {
			common.Logger().WithFields(logrus.Fields{
				"handler": handler,
			}).Debug("Updated ONU flows")
		}
	} else {
		common.Logger().WithFields(logrus.Fields{
			"handler": handler,
			"port":    table.Port,
		}).Warn("Unknown device")
	}

	common.Logger().WithFields(logrus.Fields{
		"handler": handler,
		"table":   table,
	}).Info("Updated flows")

	out := new(empty.Empty)
	return out, nil
}

/*
GetStats retrieves statistics for a PonSim device
*/
func (handler *PonSimHandler) GetStats(
	ctx context.Context,
	req *voltha.PonSimMetricsRequest,
) (*voltha.PonSimMetrics, error) {
	common.Logger().WithFields(logrus.Fields{
		"handler": handler,
	}).Info("Retrieving stats")

	var metrics *voltha.PonSimMetrics = new(voltha.PonSimMetrics)

	if olt, ok := (handler.device).(*core.PonSimOltDevice); ok {
		common.Logger().WithFields(logrus.Fields{
			"handler": handler,
			"olt":     olt,
		}).Debug("Retrieving stats for OLT")

		if req.Port == 0 {
			// port == 0, return the OLT statistics
			metrics = (handler.device).(*core.PonSimOltDevice).Counter.MakeProto()
		} else {
			common.Logger().WithFields(logrus.Fields{
			    "handler": handler,
			    "port":   req.Port,
			}).Debug("Request is for ONU")

			// port != 0, contact the ONU, retrieve onu statistics, and return to the caller
			if child, ok := (handler.device).(*core.PonSimOltDevice).GetOnus()[req.Port]; ok {
				host := strings.Join([]string{child.Device.Address, strconv.Itoa(int(child.Device.Port))}, ":")
				conn, err := grpc.Dial(
					host,
					grpc.WithInsecure(),
				)
				if err != nil {
					common.Logger().WithFields(logrus.Fields{
					    "handler": handler,
					    "error":   err.Error(),
					}).Error("GRPC Connection problem")
				}
				defer conn.Close()
				client := voltha.NewPonSimClient(conn)

				if onu_stats, err := client.GetStats(ctx, req); err != nil {
					common.Logger().WithFields(logrus.Fields{
					    "handler": handler,
					    "host":    host,
					    "error":   err.Error(),
					}).Error("Problem forwarding stats request to ONU")
				} else {
					metrics = onu_stats
				}
			} else {
				common.Logger().WithFields(logrus.Fields{
					"handler": handler,
					"port":    req.Port,
				}).Warn("Unable to find ONU")
			}
		}

		common.Logger().WithFields(logrus.Fields{
			"handler": handler,
			"metrics": metrics,
		}).Debug("OLT Metrics")

	} else if onu, ok := (handler.device).(*core.PonSimOnuDevice); ok {
		common.Logger().WithFields(logrus.Fields{
			"handler": handler,
			"onu":     onu,
		}).Debug("Retrieving stats for ONU")
		metrics = (handler.device).(*core.PonSimOnuDevice).Counter.MakeProto()
		common.Logger().WithFields(logrus.Fields{
			"handler": handler,
			"metrics": metrics,
		}).Debug("ONU Metrics")
	} else {
		common.Logger().WithFields(logrus.Fields{
			"handler": handler,
		}).Warn("Unknown device")
	}

	common.Logger().WithFields(logrus.Fields{
		"handler": handler,
	}).Info("Retrieved stats")

	return metrics, nil
}
