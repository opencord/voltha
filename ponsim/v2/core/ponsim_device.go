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
	"net"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/protos/go/openflow_13"
	"github.com/sirupsen/logrus"
)

// TODO: Pass-in the certificate information as a structure parameter
// TODO: Add certification information

type PonSimDevice struct {
	Name        string               `json:name`
	Port        int32                `json:port`
	Address     string               `json:address`
	ExternalIf  string               `json:external_if`
	InternalIf  string               `json:internal_if`
	Promiscuous bool                 `json:promiscuous`
	SnapshotLen int32                `json:snapshot_len`
	AlarmsOn    bool                 `json:alarm_on`
	AlarmsFreq  int                  `json:alarm_freq`
	Counter     *PonSimMetricCounter `json:counter`

	//*grpc.GrpcSecurity

	flows          []*openflow_13.OfpFlowStats `json:-`
	ingressHandler *pcap.Handle                `json:-`
	egressHandler  *pcap.Handle                `json:-`
	links          map[int]map[int]interface{} `json:-`
}

const (
	UDP_DST  = 1
	UDP_SRC  = 2
	IPV4_DST = 4
	VLAN_PCP = 8
	VLAN_VID = 16
	IP_PROTO = 32
	ETH_TYPE = 64
	IN_PORT  = 128
)

/*
Start performs common setup operations for a ponsim device
*/
func (o *PonSimDevice) Start(ctx context.Context) {
}

/*
Stop performs common cleanup operations for a ponsim device
*/
func (o *PonSimDevice) Stop(ctx context.Context) {
}

/*
GetAddress returns the IP/FQDN for the device
*/
func (o *PonSimDevice) GetAddress() string {
	return o.Address
}

/*
GetPort return the port assigned to the device
*/
func (o *PonSimDevice) GetPort() int32 {
	return o.Port
}

/*
Forward is responsible of processing incoming data, filtering it and redirecting to the
intended destination
*/
func (o *PonSimDevice) Forward(
	ctx context.Context,
	port int,
	frame gopacket.Packet,
) error {
	common.Logger().WithFields(logrus.Fields{
		"device": o,
		"port":   port,
		"frame":  frame,
	}).Debug("Forwarding packet")

	var err error

	o.Counter.CountRxFrame(port, len(common.GetEthernetLayer(frame).Payload))

	if egressPort, egressFrame := o.processFrame(ctx, port, frame); egressFrame != nil {
		o.SendOut(int(egressPort), egressFrame)
	} else {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"port":   int(egressPort),
			"frame":  egressFrame,
		}).Error("Failed to properly process frame")
	}

	return err
}

/*
SendOut send a given frame out the given port
*/
func (o *PonSimDevice) SendOut(
	egressPort int,
	egressFrame gopacket.Packet,
) {
	common.Logger().WithFields(logrus.Fields{
		"egressPort":  egressPort,
		"egressFrame": egressFrame,
	}).Debug("Sending packet out port")

	forwarded := 0
	links := o.links[egressPort]

	if egressPort <= 2 && egressPort > 0 {
		o.Counter.CountTxFrame(egressPort, len(common.GetEthernetLayer(egressFrame).Payload))
	}

	for _, link := range links {
		forwarded++

		common.Logger().WithFields(logrus.Fields{
			"device":      o,
			"egressPort":  egressPort,
			"egressFrame": egressFrame,
		}).Debug("Forwarding packet to link")

		link.(func(int, gopacket.Packet))(egressPort, egressFrame)
	}
	if forwarded == 0 {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"egressPort":   egressPort,
			"egressFrame":  egressFrame,
		}).Warn("Nothing was forwarded")
	}
}

/*
connectNetworkInterfaces opens network interfaces for reading and/or writing packets
*/
func (o *PonSimDevice) connectNetworkInterfaces() {
	common.Logger().WithFields(logrus.Fields{
		"device": o,
	}).Debug("Opening network interfaces")

	var err error
	if o.ingressHandler, err = pcap.OpenLive(
		o.ExternalIf, o.SnapshotLen, o.Promiscuous, pcap.BlockForever,
	); err != nil {
		common.Logger().WithFields(logrus.Fields{
			"device":    o,
			"interface": o.ExternalIf,
			"error":     err.Error(),
		}).Fatal("Unable to open Ingress interface")
	} else {
		common.Logger().WithFields(logrus.Fields{
			"device":    o,
			"interface": o.ExternalIf,
		}).Info("Opened Ingress interface")
	}

	if o.egressHandler, err = pcap.OpenLive(
		o.InternalIf, o.SnapshotLen, o.Promiscuous, pcap.BlockForever,
	); err != nil {
		common.Logger().WithFields(logrus.Fields{
			"device":    o,
			"interface": o.InternalIf,
			"error":     err.Error(),
		}).Fatal("Unable to open egress interface")
	} else {
		common.Logger().WithFields(logrus.Fields{
			"device":    o,
			"interface": o.InternalIf,
		}).Info("Opened egress interface")
	}
}

/*
AddLink assigns a functional operation to a device endpoint

The functional operation is called whenever a packet has been processed
and the endpoint has been identified as the outgoing interface
*/
func (o *PonSimDevice) AddLink(
	port int,
	index int,
	function interface{},
) error {
	common.Logger().WithFields(logrus.Fields{
		"device": o,
		"port":   port,
		"index":  index,
	}).Debug("Linking port to functional operation")

	if o.links == nil {
		o.links = make(map[int]map[int]interface{})
	}
	if _, ok := o.links[port]; !ok {
		o.links[port] = make(map[int]interface{})
	}
	o.links[port][index] = function

	return nil
}

/*
RemoveLink will remove reference a functional operation for a given port and index
*/
func (o *PonSimDevice) RemoveLink(
	port int,
	index int,
) error {
	if _, hasPort := o.links[port]; hasPort {
		if _, hasIndex := o.links[port][index]; hasIndex {
			common.Logger().WithFields(logrus.Fields{
				"device": o,
				"port":   port,
				"index":  index,
			}).Debug("Removing link functional operation")

			delete(o.links[port], index)

		} else {
			common.Logger().WithFields(logrus.Fields{
				"device": o,
				"port":   port,
				"index":  index,
			}).Warn("No such index for link functional operation")

		}
	} else {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"port":   port,
			"index":  index,
		}).Warn("No such port for functional operation")
	}

	return nil
}

/*
InstallFlows assigns flows to the device in order of priority
*/
func (o *PonSimDevice) InstallFlows(
	ctx context.Context,
	flows []*openflow_13.OfpFlowStats,
) error {
	common.Logger().WithFields(logrus.Fields{
		"device": o,
		"flows":  flows,
	}).Debug("Installing flows")

	o.flows = flows
	sort.Sort(sort.Reverse(common.SortByPriority(o.flows)))

	common.Logger().WithFields(logrus.Fields{
		"device": o,
	}).Debug("Installed sorted flows")

	return nil
}

/*
processFrame is responsible for matching or discarding a frame based on the configured flows
*/
func (o *PonSimDevice) processFrame(
	ctx context.Context,
	port int,
	frame gopacket.Packet,
) (uint32, gopacket.Packet) {
	common.Logger().WithFields(logrus.Fields{
		"device": o,
		"port":   port,
		"frame":  frame,
	}).Debug("Processing frame")

	var err error
	var matchedMask int = 0
	var currentMask int
	var highestPriority uint32 = 0
	var matchedFlow *openflow_13.OfpFlowStats = nil

	common.Logger().WithFields(logrus.Fields{
		"device": o,
	}).Debug("Looping through flows")

	for _, flow := range o.flows {
		common.Logger().WithFields(logrus.Fields{
			"device": o,
			"flow":   flow,
		}).Debug("Checking flow")

		if matchedFlow != nil && flow.Priority < highestPriority {
			common.Logger().WithFields(logrus.Fields{
				"device":      o,
				"matchedFlow": matchedFlow,
				"priority":    highestPriority,
			}).Debug("Flow has already been matched")
			break
		} else {
			common.Logger().WithFields(logrus.Fields{
				"device":          o,
				"matchedFlow":     matchedFlow,
				"priority":        flow.Priority,
				"highestPriority": highestPriority,
			}).Debug("Flow OR Priority requirements not met")
		}

		highestPriority = flow.Priority
		if currentMask, err = o.isMatch(ctx, flow, port, frame); err != nil {
			common.Logger().WithFields(logrus.Fields{
				"device": o,
				"flow":   flow,
				"port":   port,
				"frame":  frame,
				"error":  err.Error(),
			}).Error("Problem while matching flow")

		} else if currentMask > matchedMask {
			matchedMask = currentMask
			matchedFlow = flow

			common.Logger().WithFields(logrus.Fields{
				"device":      o,
				"matchedFlow": flow,
				"port":        port,
				"frame":       frame,
				"matchedMask": matchedMask,
			}).Debug("Flow matches")
		}
	}

	if matchedFlow != nil {
		egressPort, egressFrame := o.processActions(ctx, matchedFlow, frame)

		common.Logger().WithFields(logrus.Fields{
			"device":      o,
			"port":        port,
			"egressPort":  egressPort,
			"egressFrame": egressFrame,
		}).Debug("Processed actions to matched flow")

		return egressPort, egressFrame
	} else {
		common.Logger().WithFields(logrus.Fields{
			"device":      o,
			"port":        port,
			"frame":       frame,
			"matchedMask": matchedMask,
		}).Warn("Flow was not successfully matched")
	}

	return 0, nil
}

/*
isMatch traverses the criteria of a flow and identify all matching elements of a frame (if any)
*/
func (o *PonSimDevice) isMatch(
	ctx context.Context,
	flow *openflow_13.OfpFlowStats,
	port int,
	frame gopacket.Packet,
) (int, error) {
	matchedMask := 0

	for _, ofbfield := range flow.Match.OxmFields {
		if ofbfield.GetOxmClass() == openflow_13.OfpOxmClass_OFPXMC_OPENFLOW_BASIC {
			switch ofbfield.GetOfbField().Type {
			case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_IN_PORT:
				if ofbfield.GetOfbField().GetPort() != uint32(port) {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": ofbfield.GetOfbField().GetPort(),
						"actual":   port,
					}).Warn("Port does not match")
					return 0, nil
				} else {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": ofbfield.GetOfbField().GetPort(),
						"actual":   port,
					}).Debug("Port matches")
				}
				matchedMask |= IN_PORT

			case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_ETH_TYPE:
				cmpType := uint32(common.GetEthernetLayer(frame).EthernetType)
				if dot1q := common.GetLastDot1QLayer(frame); dot1q != nil {
					cmpType = uint32(dot1q.Type)
				}
				if ofbfield.GetOfbField().GetEthType() != cmpType {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": layers.EthernetType(ofbfield.GetOfbField().GetEthType()),
						"actual":   cmpType,
					}).Warn("Frame type does not match")
					return 0, nil
				} else {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": layers.EthernetType(ofbfield.GetOfbField().GetEthType()),
						"actual":   cmpType,
					}).Debug("Frame type matches")
				}
				matchedMask |= ETH_TYPE

			case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_IP_PROTO:
				if ofbfield.GetOfbField().GetIpProto() != uint32(common.GetIpLayer(frame).Protocol) {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": ofbfield.GetOfbField().GetIpProto(),
						"actual":   common.GetIpLayer(frame).Protocol,
					}).Warn("IP protocol does not match")
					return 0, nil
				} else {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": ofbfield.GetOfbField().GetIpProto(),
						"actual":   common.GetIpLayer(frame).Protocol,
					}).Debug("IP protocol matches")
				}
				matchedMask |= IP_PROTO

			case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_VID:
				expectedVlan := ofbfield.GetOfbField().GetVlanVid()
				dot1q := common.GetDot1QLayer(frame)

				if (expectedVlan&4096 == 0) != (dot1q == nil) {
					common.Logger().WithFields(logrus.Fields{
						"device":       o,
						"flow":         flow,
						"expectedVlan": expectedVlan,
						"vlanBitwise":  expectedVlan & 4096,
						"dot1q":        dot1q,
					}).Warn("VLAN condition not met")
					return 0, nil
				}
				if dot1q != nil {
					if uint32(dot1q.VLANIdentifier) != (expectedVlan & 4095) {
						common.Logger().WithFields(logrus.Fields{
							"device":   o,
							"flow":     flow,
							"expected": expectedVlan,
							"actual":   uint32(dot1q.VLANIdentifier),
						}).Warn("VLAN VID does not match")
						return 0, nil
					} else {
						common.Logger().WithFields(logrus.Fields{
							"device":   o,
							"flow":     flow,
							"expected": expectedVlan,
							"actual":   uint32(dot1q.VLANIdentifier),
						}).Debug("VLAN VID matches")
					}
				} else {
					common.Logger().WithFields(logrus.Fields{
						"device": o,
						"flow":   flow,
					}).Warn("VLAN VID missing. Not dot1q encapsulation")
				}
				matchedMask |= VLAN_VID

			case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_PCP:
				if ofbfield.GetOfbField().GetVlanPcp() != uint32(common.GetDot1QLayer(frame).Priority) {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": ofbfield.GetOfbField().GetVlanPcp(),
						"actual":   uint32(common.GetDot1QLayer(frame).Priority),
					}).Warn("VLAN priority does not match")
					return 0, nil
				} else {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": ofbfield.GetOfbField().GetVlanPcp(),
						"actual":   uint32(common.GetDot1QLayer(frame).Priority),
					}).Debug("VLAN priority matches")
				}
				matchedMask |= VLAN_PCP

			case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_IPV4_DST:
				dstIpRaw := ofbfield.GetOfbField().GetIpv4Dst()
				dstIp := net.IPv4(
					byte((dstIpRaw>>24)&0xFF),
					byte((dstIpRaw>>16)&0xFF),
					byte((dstIpRaw>>8)&0xFF),
					byte(dstIpRaw&0xFF))

				if !dstIp.Equal(common.GetIpLayer(frame).DstIP) {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": dstIp,
						"actual":   common.GetIpLayer(frame).DstIP,
					}).Warn("IPv4 destination does not match")
					return 0, nil
				} else {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": dstIp,
						"actual":   common.GetIpLayer(frame).DstIP,
					}).Debug("IPv4 destination matches")

				}
				matchedMask |= IPV4_DST

			case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_UDP_SRC:
				if ofbfield.GetOfbField().GetUdpSrc() != uint32(common.GetUdpLayer(frame).SrcPort) {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": ofbfield.GetOfbField().GetUdpSrc(),
						"actual":   common.GetUdpLayer(frame).SrcPort,
					}).Warn("UDP source port does not match")
					return 0, nil
				} else {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": ofbfield.GetOfbField().GetUdpSrc(),
						"actual":   common.GetUdpLayer(frame).SrcPort,
					}).Debug("UDP source port matches")
				}
				matchedMask |= UDP_SRC

			case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_UDP_DST:
				if ofbfield.GetOfbField().GetUdpDst() != uint32(common.GetUdpLayer(frame).DstPort) {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": ofbfield.GetOfbField().GetUdpDst(),
						"actual":   common.GetUdpLayer(frame).DstPort,
					}).Warn("UDP destination port does not match")
					return 0, nil
				} else {
					common.Logger().WithFields(logrus.Fields{
						"device":   o,
						"flow":     flow,
						"expected": ofbfield.GetOfbField().GetUdpDst(),
						"actual":   common.GetUdpLayer(frame).DstPort,
					}).Debug("UDP destination port does matches")
				}
				matchedMask |= UDP_DST

			case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_METADATA:
				common.Logger().WithFields(logrus.Fields{
					"device": o,
					"flow":   flow,
				}).Warn("Skipping metadata")
				continue

			default:
				common.Logger().WithFields(logrus.Fields{
					"device": o,
					"flow":   flow,
					"type":   ofbfield.GetOfbField().Type,
				}).Warn("Field type not implemented")
			}
		}
	}
	return matchedMask, nil
}

/*
processActions applies transformation instructions to a frame that met all the flow criteria
*/
func (o *PonSimDevice) processActions(
	ctx context.Context,
	flow *openflow_13.OfpFlowStats,
	frame gopacket.Packet,
) (uint32, gopacket.Packet) {
	var egressPort uint32
	var retFrame gopacket.Packet = frame

	common.Logger().WithFields(logrus.Fields{
		"device": o,
		"flow":   flow,
		"frame":  retFrame,
	}).Info("Processing actions")

	for _, instruction := range flow.Instructions {
		common.Logger().WithFields(logrus.Fields{
			"device":      o,
			"flow":        flow,
			"frame":       retFrame,
			"instruction": instruction,
		}).Debug("Processing actions - Instruction entry")
		if instruction.Type == uint32(openflow_13.OfpInstructionType_OFPIT_APPLY_ACTIONS) {
			for _, action := range instruction.GetActions().GetActions() {
				common.Logger().WithFields(logrus.Fields{
					"device":     o,
					"flow":       flow,
					"frame":      retFrame,
					"action":     action,
					"actionType": action.Type,
				}).Debug("Processing actions - Action entry")

				switch action.Type {
				case openflow_13.OfpActionType_OFPAT_OUTPUT:
					common.Logger().WithFields(logrus.Fields{
						"device": o,
						"flow":   flow,
						"frame":  retFrame,
					}).Debug("Processing action OFPAT output")
					egressPort = action.GetOutput().Port

				case openflow_13.OfpActionType_OFPAT_POP_VLAN:
					common.Logger().WithFields(logrus.Fields{
						"device": o,
						"flow":   flow,
						"frame":  retFrame,
					}).Debug("Processing action OFPAT POP VLAN")
					if shim := common.GetDot1QLayer(retFrame); shim != nil {
						if eth := common.GetEthernetLayer(retFrame); eth != nil {
							ethernetLayer := &layers.Ethernet{
								SrcMAC:       eth.SrcMAC,
								DstMAC:       eth.DstMAC,
								EthernetType: shim.Type,
							}
							buffer := gopacket.NewSerializeBuffer()
							gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
								ethernetLayer,
								gopacket.Payload(shim.Payload),
							)
							retFrame = gopacket.NewPacket(
								buffer.Bytes(),
								layers.LayerTypeEthernet,
								gopacket.Default,
							)
						} else {
							common.Logger().WithFields(logrus.Fields{
								"device": o,
								"flow":   flow,
								"frame":  retFrame,
							}).Warn("No ETH found while processing POP VLAN action")
						}
					} else {
						common.Logger().WithFields(logrus.Fields{
							"device": o,
							"flow":   flow,
							"frame":  retFrame,
						}).Warn("No DOT1Q found while processing POP VLAN action")
					}
				case openflow_13.OfpActionType_OFPAT_PUSH_VLAN:
					if eth := common.GetEthernetLayer(retFrame); eth != nil {
						ethernetLayer := &layers.Ethernet{
							SrcMAC:       eth.SrcMAC,
							DstMAC:       eth.DstMAC,
							EthernetType: layers.EthernetType(action.GetPush().GetEthertype()),
						}
						dot1qLayer := &layers.Dot1Q{
							Type: eth.EthernetType,
						}

						buffer := gopacket.NewSerializeBuffer()
						gopacket.SerializeLayers(
							buffer,
							gopacket.SerializeOptions{
								FixLengths: false,
							},
							ethernetLayer,
							dot1qLayer,
							gopacket.Payload(eth.Payload),
						)
						retFrame = gopacket.NewPacket(
							buffer.Bytes(),
							layers.LayerTypeEthernet,
							gopacket.Default,
						)
					} else {
						common.Logger().WithFields(logrus.Fields{
							"device": o,
							"flow":   flow,
							"frame":  retFrame,
						}).Warn("No ETH found while processing PUSH VLAN action")
					}
				case openflow_13.OfpActionType_OFPAT_SET_FIELD:
					common.Logger().WithFields(logrus.Fields{
						"device": o,
						"flow":   flow,
						"frame":  retFrame,
					}).Debug("Processing action OFPAT SET FIELD")
					if action.GetSetField().GetField().GetOxmClass() ==
						openflow_13.OfpOxmClass_OFPXMC_OPENFLOW_BASIC {
						field := action.GetSetField().GetField().GetOfbField()

						switch field.Type {
						case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_VID:
							common.Logger().WithFields(logrus.Fields{
								"device": o,
								"flow":   flow,
								"frame":  retFrame,
							}).Debug("Processing action OFPAT SET FIELD - VLAN VID")
							if shim := common.GetDot1QLayer(retFrame); shim != nil {
								eth := common.GetEthernetLayer(retFrame)
								buffer := gopacket.NewSerializeBuffer()

								var dot1qLayer *layers.Dot1Q
								var ethernetLayer *layers.Ethernet
								ethernetLayer = &layers.Ethernet{
									SrcMAC:       eth.SrcMAC,
									DstMAC:       eth.DstMAC,
									EthernetType: eth.EthernetType,
								}

								dot1qLayer = &layers.Dot1Q{
									Type:           shim.Type,
									VLANIdentifier: uint16(field.GetVlanVid() & 4095),
								}

								gopacket.SerializeLayers(
									buffer,
									gopacket.SerializeOptions{},
									ethernetLayer,
									dot1qLayer,
									gopacket.Payload(shim.LayerPayload()),
								)
								retFrame = gopacket.NewPacket(
									buffer.Bytes(),
									layers.LayerTypeEthernet,
									gopacket.Default,
								)

								common.Logger().WithFields(logrus.Fields{
									"device":    o,
									"flow":      flow,
									"frame":     retFrame,
									"frameDump": retFrame.Dump(),
									"vlanVid":   shim.VLANIdentifier,
								}).Info("Setting DOT1Q VLAN VID")
							} else {
								common.Logger().WithFields(logrus.Fields{
									"device": o,
									"flow":   flow,
									"frame":  retFrame,
								}).Warn("No DOT1Q found while setting VLAN VID")
							}

						case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_PCP:
							common.Logger().WithFields(logrus.Fields{
								"device": o,
								"flow":   flow,
								"frame":  retFrame,
							}).Debug("Processing action OFPAT SET FIELD - VLAN PCP")
							if shim := common.GetDot1QLayer(retFrame); shim != nil {
								shim.Priority = uint8(field.GetVlanPcp())
								common.Logger().WithFields(logrus.Fields{
									"device":   o,
									"flow":     flow,
									"frame":    retFrame,
									"priority": shim.Priority,
								}).Info("Setting DOT1Q VLAN PCP")
							} else {
								common.Logger().WithFields(logrus.Fields{
									"device": o,
									"flow":   flow,
									"frame":  retFrame,
								}).Warn("No DOT1Q found while setting VLAN PCP")
							}
						default:
							common.Logger().WithFields(logrus.Fields{
								"device": o,
								"flow":   flow,
								"frame":  retFrame,
								"type":   field.Type,
							}).Warn("Set field not implemented for this type")
						}
					} else {
						common.Logger().WithFields(logrus.Fields{
							"device": o,
							"flow":   flow,
							"frame":  retFrame,
						}).Warn("Field not of type OF-BASIC")
					}
				default:
					common.Logger().WithFields(logrus.Fields{
						"device": o,
						"flow":   flow,
						"frame":  retFrame,
						"type":   action.Type,
					}).Warn("Action type not implemented")
				}
			}
		}
	}

	common.Logger().WithFields(logrus.Fields{
		"device":     o,
		"flow":       flow,
		"egressPort": egressPort,
		"retFrame":   retFrame,
	}).Debug("Processed actions")

	return egressPort, retFrame
}
