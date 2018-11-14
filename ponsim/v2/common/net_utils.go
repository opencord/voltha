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
package common

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"net"
)

func GetInterfaceIP(ifName string) string {
	var err error
	var netIf *net.Interface
	var netAddrs []net.Addr
	var netIp net.IP
	var ipAddr string

	if netIf, err = net.InterfaceByName(ifName); err == nil {
		if netAddrs, err = netIf.Addrs(); err == nil {
			for _, addr := range netAddrs {
				Logger().WithFields(logrus.Fields{
					"type": addr.Network(),
				}).Debug("Address network type")
				switch v := addr.(type) {
				case *net.IPNet:
					netIp = v.IP
				case *net.IPAddr:
					netIp = v.IP
				}
				if netIp == nil || netIp.IsLoopback() {
					continue
				}
				netIp = netIp.To4()
				if netIp == nil {
					continue // not an ipv4 address
				}
				ipAddr = netIp.String()
				break
			}
		}
	}

	return ipAddr
}
func GetHostIP(hostName string) string {
	var err error
	var ipAddrs []string
	var ipAddr string

	if ipAddrs, err = net.LookupHost(hostName); err == nil {
		for _, ip := range ipAddrs {
			if addr := net.ParseIP(ip); err == nil {
				Logger().WithFields(logrus.Fields{
					"ip": addr,
				}).Debug("Host address")
				if addr == nil /*|| addr.IsLoopback()*/ {
					continue
				}
				ipAddr = ip
				break
			}
		}
	}

	return ipAddr
}
func GetMacAddress(ifName string) net.HardwareAddr {
	var err error
	var netIf *net.Interface
	var hwAddr net.HardwareAddr

	if netIf, err = net.InterfaceByName(ifName); err == nil {
		hwAddr = netIf.HardwareAddr
	}

	return hwAddr
}

func GetEthernetLayer(frame gopacket.Packet) *layers.Ethernet {
	eth := &layers.Ethernet{}
	if ethLayer := frame.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ = ethLayer.(*layers.Ethernet)
	}
	return eth
}
func GetDot1QLayer(frame gopacket.Packet) *layers.Dot1Q {
	var dot1q *layers.Dot1Q
	//dot1q := &layers.Dot1Q{}
	if dot1qLayer := frame.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
		dot1q, _ = dot1qLayer.(*layers.Dot1Q)
	}
	return dot1q
}
func GetLastDot1QLayer(frame gopacket.Packet) *layers.Dot1Q {
	var dot1q *layers.Dot1Q
	for _, layer := range frame.Layers() {
		if layer.LayerType() == layers.LayerTypeDot1Q {
			if adot1q, _ := layer.(*layers.Dot1Q); adot1q.NextLayerType() != layers.LayerTypeDot1Q {
				dot1q = adot1q
				break
			}
		}
	}
	return dot1q
}
func GetIpLayer(frame gopacket.Packet) *layers.IPv4 {
	ip := &layers.IPv4{}
	if ipLayer := frame.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ = ipLayer.(*layers.IPv4)
	}
	return ip
}
func GetUdpLayer(frame gopacket.Packet) *layers.UDP {
	udp := &layers.UDP{}
	if udpLayer := frame.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ = udpLayer.(*layers.UDP)
	}
	return udp
}
