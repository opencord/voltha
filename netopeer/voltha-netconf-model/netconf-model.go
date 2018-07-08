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
//package netconf-model
package main

/*
#include <stdlib.h>
#include <voltha-defs.h>
*/
import "C"

import (
	"log"
	"encoding/xml"
	"unsafe"
)

func init() {
}

// ----------------------------------------------
// Data structures
// ----------------------------------------------

type Adapter struct {
}

type Adapters struct {
	XMLName xml.Name `xml:"adapters"`
	Items   []Adapter
}

type LogicalDevice struct {
}

type LogicalDevices struct {
	XMLName xml.Name `xml:"logical_devices"`
	Items   []LogicalDevice
}

type DeviceGroup struct {
}

type DeviceGroups struct {
	XMLName xml.Name `xml:"device_groups"`
	Items   []Device
}

type DeviceType struct {
}

type DeviceTypes struct {
	XMLName xml.Name `xml:"device_types"`
	Items   []DeviceType
}

type AlarmFilter struct {
}

type AlarmFilters struct {
	XMLName xml.Name `xml:"alarm_filters"`
	Items   []AlarmFilter
}

type Custom struct {
}

type ProxyAddress struct {
}

type Port struct {
}

type Ports struct {
	XMLName xml.Name `xml:"ports"`
	Items   []Port
}

type Flow struct {
}

type Flows struct {
	XMLName xml.Name `xml:"flows"`
	Items   []Flow
}

type FlowGroup struct {
}

type FlowGroups struct {
	XMLName xml.Name `xml:"flow_groups"`
	Items   []FlowGroup
}

type PmConfig struct {
}

type PmConfigs struct {
	XMLName xml.Name `xml:"pm_configs"`
	Items   []PmConfig
}

type Address struct {
	MacAddress  string `xml:"mac_address,omitempty"`
	Ipv4Address string `xml:"ipv4_address,omitempty"`
	Ipv6Address string `xml:"ipv6_address,omitempty"`
	HostAndPort string `xml:"host_and_port,omitempty"`
}
type Device struct {
	XMLName         xml.Name `xml:"device"`
	Id              string `xml:"id"`
	Type            string `xml:"type"`
	Root            int `xml:"root"`
	ParentId        string `xml:"parent_id"`
	ParentPortNo    int `xml:"parent_port_no"`
	Vendor          string `xml:"vendor"`
	Model           string `xml:"model"`
	HardwareVersion string `xml:"hardware_version"`
	FirmwareVersion string `xml:"firmware_version"`
	SoftwareVersion string `xml:"software_version"`
	Adapter         string `xml:"adapter"`
	Vlan            int `xml:"vlan"`
	ProxyAddress    ProxyAddress `xml:"proxy_address"`
	AdminState      string `xml:"admin_state"`
	OperStatus      string `xml:"oper_status"`
	Reason          string `xml:"reason"`
	ConnectStatus   string `xml:"connect_status"`
	Custom          Custom `xml:"custom"`
	Ports           Ports `xml:"ports"`
	Flows           Flows `xml:"flows"`
	FlowGroups      FlowGroups `xml:"flow_groups"`
	PmConfigs       PmConfigs `xml:"pm_configs"`
	Address
}
type Devices struct {
	XMLName xml.Name `xml:"devices"`
	Items   []Device
}

type HealthStatus struct {
	XMLName xml.Name `xml:"health"`
	State   string `xml:"state"`
}
type Voltha struct {
	XMLName        xml.Name `xml:"voltha"`
	Version        string `xml:"version"`
	LogLevel       string `xml:"log_level"`
	Instances      VolthaInstances `xml:"instances"`
	Adapters       Adapters `xml:"adapters"`
	LogicalDevices LogicalDevices `xml:"logical_devices"`
	Devices        Devices `xml:"devices"`
	DeviceGroups   DeviceGroups `xml:"device_groups"`
}
type VolthaInstance struct {
	XMLName        xml.Name `xml:"voltha_instance"`
	InstanceId     string `xml:"instance_id"`
	Version        string `xml:"version"`
	LogLevel       string `xml:"log_level"`
	HealthStatus   string `xml:"health"`
	Adapters       Adapters `xml:"adapters"`
	LogicalDevices LogicalDevices `xml:"logical_devices"`
	Devices        Devices `xml:"devices"`
	DeviceTypes    DeviceTypes `xml:"device_types"`
	DeviceGroups   DeviceGroups `xml:"device_groups"`
	AlarmFilters   AlarmFilters `xml:"alarm_filters"`
}
type VolthaInstances struct {
	Items []VolthaInstance `xml:"items"`
}

// ----------------------------------------------
// Conversion utility methods
// ----------------------------------------------

func _constructVolthaInstances(instances C.VolthaInstanceArray) VolthaInstances {
	var v VolthaInstances
	var item VolthaInstance
	var c_instance C.VolthaInstance

	length := instances.size
	c_instances := (*[1 << 30]C.VolthaInstance)(unsafe.Pointer(instances.items))[:length:length]

	for i := 0; i < int(instances.size); i += 1 {
		c_instance = c_instances[i]
		item.InstanceId = C.GoString(c_instance.InstanceId)
		item.Version = C.GoString(c_instance.Version)
		item.LogLevel = C.GoString(c_instance.LogLevel)
		//item.HealthStatus = C.GoString(c_instance.Health)
		item.Adapters = _constructAdapters(c_instance.Adapters)
		item.LogicalDevices = _constructLogicalDevices(c_instance.LogicalDevices)
		item.Devices = _constructDevices(c_instance.Devices)
		item.DeviceTypes = _constructDeviceTypes(c_instance.DeviceTypes)
		item.DeviceGroups = _constructDeviceGroups(c_instance.DeviceGroups)
		item.AlarmFilters = _constructAlarmFilters(c_instance.AlarmFilters)

		v.Items = append(v.Items, item)
	}

	return v
}
func _constructAdapters(instances C.AdapterArray) Adapters {
	return Adapters{}
}
func _constructLogicalDevices(instances C.LogicalDeviceArray) LogicalDevices {
	return LogicalDevices{}
}
func _constructDevices(instances C.DeviceArray) Devices {
	var d Devices
	var item Device
	var c_instance C.Device

	length := instances.size
	log.Printf("number of instances : %d", length)
	c_instances := (*[1 << 30]C.Device)(unsafe.Pointer(instances.items))[:length:length]

	for i := 0; i < int(instances.size); i += 1 {
		c_instance = c_instances[i]

		item = _constructDevice(c_instance)

		d.Items = append(d.Items, item)
	}

	return d
}
func _constructDeviceGroups(instances C.DeviceGroupArray) DeviceGroups {
	return DeviceGroups{}
}
func _constructDeviceTypes(instances C.DeviceTypeArray) DeviceTypes {
	return DeviceTypes{}
}
func _constructAlarmFilters(instances C.AlarmFilterArray) AlarmFilters {
	return AlarmFilters{}
}
func _constructVoltha(voltha C.Voltha) Voltha {
	return Voltha{
		Version:        C.GoString(voltha.Version),
		LogLevel:       C.GoString(voltha.LogLevel),
		Instances:      _constructVolthaInstances(voltha.Instances),
		Adapters:       _constructAdapters(voltha.Adapters),
		LogicalDevices: _constructLogicalDevices(voltha.LogicalDevices),
		Devices:        _constructDevices(voltha.Devices),
		DeviceGroups:   _constructDeviceGroups(voltha.DeviceGroups),
	}
}
func _constructProxyAddress(proxyAddress *C.Device_ProxyAddress) ProxyAddress {
	return ProxyAddress{}
}
func _constructPorts(ports C.PortArray) Ports {
	return Ports{}
}
func _constructFlows(flows *C.Flows) Flows {
	return Flows{}
}
func _constructFlowGroups(flowGroups *C.FlowGroups) FlowGroups {
	return FlowGroups{}
}
func _constructPmConfigs(pmConfigs *C.PmConfigs) PmConfigs {
	return PmConfigs{}
}
func _constructAddress(address C.isDevice_Address) Address {
	var a Address
	switch address.Type {
	case C.MAC:
		a.MacAddress = C.GoString(address.Value)
	case C.IPV4:
		a.Ipv4Address = C.GoString(address.Value)
	case C.IPV6:
		a.Ipv6Address = C.GoString(address.Value)
	case C.HOST_AND_PORT:
		a.HostAndPort = C.GoString(address.Value)
	}
	return a
}

func _constructDevice(device C.Device) Device {
	d := Device{
		Id:              C.GoString(device.Id),
		Type:            C.GoString(device.Type),
		Root:            int(device.Root),
		ParentId:        C.GoString(device.ParentId),
		ParentPortNo:    int(device.ParentPortNo),
		Vendor:          C.GoString(device.Vendor),
		Model:           C.GoString(device.Model),
		HardwareVersion: C.GoString(device.HardwareVersion),
		FirmwareVersion: C.GoString(device.FirmwareVersion),
		SoftwareVersion: C.GoString(device.SoftwareVersion),
		Adapter:         C.GoString(device.Adapter),
		Vlan:            int(device.Vlan),
		ProxyAddress:    _constructProxyAddress(device.ProxyAddress),
		AdminState:      C.GoString(device.AdminState),
		OperStatus:      C.GoString(device.OperStatus),
		Reason:          C.GoString(device.Reason),
		ConnectStatus:   C.GoString(device.ConnectStatus),
		Ports:           _constructPorts(device.Ports),
		Flows:           _constructFlows(device.Flows),
		FlowGroups:      _constructFlowGroups(device.FlowGroups),
		PmConfigs:       _constructPmConfigs(device.PmConfigs),
		Address:         _constructAddress(device.Address),
	}

	return d
}

func _constructHealthStatus(health C.HealthStatus) HealthStatus {
	return HealthStatus{
		State: C.GoString(health.State),
	}
}

// ----------------------------------------------
// Exported translation methods
// ----------------------------------------------

//export TranslateVoltha
func TranslateVoltha(voltha C.Voltha) *C.char {
	var err error
	var data []byte
	var cs *C.char;
	defer C.free(unsafe.Pointer(cs))

	v := _constructVoltha(voltha)

	if data, err = xml.Marshal(v); err != nil {
		log.Printf("ERROR While marshalling: %s", err.Error())
	}

	cs = C.CString(string(data))

	return cs
}

//export TranslateDevice
func TranslateDevice(device C.Device) *C.char {
	var err error
	var data []byte
	var cs *C.char;
	defer C.free(unsafe.Pointer(cs))

	d := _constructDevice(device)

	if data, err = xml.Marshal(d); err != nil {
		log.Printf("ERROR While marshalling: %s", err.Error())
	}

	cs = C.CString(string(data))

	return cs
}

//export TranslateDevices
func TranslateDevices(devices C.DeviceArray) *C.char {
	var err error
	var data []byte
	var cs *C.char;
	defer C.free(unsafe.Pointer(cs))

	d := _constructDevices(devices)

	if data, err = xml.Marshal(d); err != nil {
		log.Printf("ERROR While marshalling: %s", err.Error())
	}

	cs = C.CString(string(data))

	return cs
}

//export TranslateHealthStatus
func TranslateHealthStatus(health C.HealthStatus) *C.char {
	var err error
	var data []byte
	var cs *C.char;
	defer C.free(unsafe.Pointer(cs))

	d := _constructHealthStatus(health)

	if data, err = xml.Marshal(d); err != nil {
		log.Printf("ERROR While marshalling: %s", err.Error())
	}

	cs = C.CString(string(data))

	return cs
}

func main() {
	// We need the main function to make possible
	// CGO compiler to compile the package as C shared library
}
