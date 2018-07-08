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
//package voltha
package main

/*
#include <stdlib.h>
#include "voltha-defs.h"
 */
import "C"

import (
	"log"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/consul/api"
	pb "github.com/opencord/voltha/netconf/translator/voltha"
	pb_health "github.com/opencord/voltha/netconf/translator/voltha/health"
	pb_device "github.com/opencord/voltha/netconf/translator/voltha/device"
	pb_adapter "github.com/opencord/voltha/netconf/translator/voltha/adapter"
	pb_logical_device "github.com/opencord/voltha/netconf/translator/voltha/logical_device"
	pb_openflow "github.com/opencord/voltha/netconf/translator/voltha/openflow_13"
	pb_any "github.com/golang/protobuf/ptypes/any"
	"unsafe"
	"fmt"
)

const (
	default_consul_address = "10.100.198.220:8500"
	default_grpc_address   = "localhost:50555"
	grpc_service_name      = "voltha-grpc"
)

var (
	GrpcConn           *grpc.ClientConn              = nil
	VolthaGlobalClient pb.VolthaGlobalServiceClient  = nil
	HealthClient       pb_health.HealthServiceClient = nil
	ConsulClient       *api.Client                   = nil
	GrpcServiceAddress string                        = "localhost:50555"
)

func init() {
	ConsulClient = connect_to_consul(default_consul_address)
	GrpcServiceAddress = get_consul_service_address(grpc_service_name)
	GrpcConn = connect_to_grpc(GrpcServiceAddress)

	VolthaGlobalClient = pb.NewVolthaGlobalServiceClient(GrpcConn)
	HealthClient = pb_health.NewHealthServiceClient(GrpcConn)
}

func connect_to_consul(consul_address string) *api.Client {
	cfg := api.Config{Address: consul_address }

	log.Printf("Connecting to consul - address: %s", consul_address)

	client, err := api.NewClient(&cfg)
	if err != nil {
		panic(err)
	}

	log.Printf("Connected to consul - address: %s", consul_address)

	return client
}

func get_consul_service_address(service_name string) string {
	var service []*api.CatalogService
	var err error

	log.Printf("Getting consul service - name:%s", service_name)

	if service, _, _ = ConsulClient.Catalog().Service(service_name, "", nil); err != nil {
		panic(err)
	}

	address := fmt.Sprintf("%s:%d", service[0].ServiceAddress, service[0].ServicePort)

	log.Printf("Got consul service - name:%s, address:%s", service_name, address)

	return address
}

func connect_to_grpc(grpc_address string) *grpc.ClientConn {
	var err error
	var client *grpc.ClientConn

	log.Printf("Connecting to grpc - address: %s", grpc_address)

	// Set up a connection to the server.
	client, err = grpc.Dial(grpc_address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err.Error())
	}

	log.Printf("Connected to grpc - address: %s", grpc_address)

	return client
}
// Utility methods

// -------------------------------------------------
// C to Protobuf conversion methods
// -------------------------------------------------

func _c_to_proto_Address(address C.isDevice_Address) *pb_device.Device {
	var device *pb_device.Device

	// Identify the address type to assign
	switch address.Type {
	case C.MAC:
		device.Address = &pb_device.Device_MacAddress{
			MacAddress: C.GoString(address.Value),
		}
		break
	case C.IPV4:
		device.Address = &pb_device.Device_Ipv4Address{
			Ipv4Address: C.GoString(address.Value),
		}
		break
	case C.IPV6:
		device.Address = &pb_device.Device_Ipv6Address{
			Ipv6Address: C.GoString(address.Value),
		}
		break
	case C.HOST_AND_PORT:
		device.Address = &pb_device.Device_HostAndPort{
			HostAndPort: C.GoString(address.Value),
		}
		break
	}

	return device
}

// -------------------------------------------------
// Protobuf to C conversion methods
// -------------------------------------------------

func _proto_to_c_Adapters(instances []*pb_adapter.Adapter) C.AdapterArray {
	// TODO: not implemented
	var result C.AdapterArray
	return result
}
func _proto_to_c_LogicalDevices(instances []*pb_logical_device.LogicalDevice) C.LogicalDeviceArray {
	// TODO: not implemented
	var result C.LogicalDeviceArray
	return result
}
func _proto_to_c_DeviceTypes(instances []*pb_device.DeviceType) C.DeviceTypeArray {
	// TODO: not implemented
	var result C.DeviceTypeArray
	return result
}
func _proto_to_c_AlarmFilters(instances []*pb.AlarmFilter) C.AlarmFilterArray {
	// TODO: not implemented
	var result C.AlarmFilterArray
	return result
}
func _proto_to_c_DeviceGroups(instances []*pb.DeviceGroup) C.DeviceGroupArray {
	// TODO: not implemented
	var result C.DeviceGroupArray
	return result
}
func _proto_to_c_ProxyAddress(proxyAddress *pb_device.Device_ProxyAddress) *C.Device_ProxyAddress {
	// TODO: not implemented
	var result *C.Device_ProxyAddress
	defer C.free(unsafe.Pointer(result))
	return result
}
func _proto_to_c_Ports(ports []*pb_device.Port) C.PortArray {
	// TODO: not implemented
	var result C.PortArray
	return result
}
func _proto_to_c_Flows(flows *pb_openflow.Flows) *C.Flows {
	// TODO: not implemented
	var result *C.Flows
	defer C.free(unsafe.Pointer(result))
	return result
}
func _proto_to_c_FlowGroups(groups *pb_openflow.FlowGroups) *C.FlowGroups {
	// TODO: not implemented
	var result *C.FlowGroups
	defer C.free(unsafe.Pointer(result))
	return result
}
func _proto_to_c_PmConfigs(configs *pb_device.PmConfigs) *C.PmConfigs {
	// TODO: not implemented
	var result *C.PmConfigs
	defer C.free(unsafe.Pointer(result))
	return result
}
func _proto_to_c_Custom(configs *pb_any.Any) *C.Any {
	// TODO: not implemented
	var result *C.Any
	defer C.free(unsafe.Pointer(result))
	return result
}
func _proto_to_c_HealthStatus(health *pb_health.HealthStatus) C.HealthStatus {
	var result C.HealthStatus

	var c_string *C.char
	defer C.free(unsafe.Pointer(c_string))

	if c_string = C.CString(health.GetState().String()); c_string != nil {
		result.State = c_string
	}

	return result
}

func _proto_to_c_VolthaInstances(instances []*pb.VolthaInstance) C.VolthaInstanceArray {
	var result C.VolthaInstanceArray
	var c_string *C.char
	var c_voltha_instance C.VolthaInstance
	defer C.free(unsafe.Pointer(c_string))

	sizeof := unsafe.Sizeof(c_voltha_instance)
	count := len(instances)
	result.size = C.int(count)

	c_items := C.malloc(C.size_t(result.size) * C.size_t(sizeof))
	defer C.free(unsafe.Pointer(c_items))

	// Array to the allocated space
	c_array := (*[1<<30 - 1]C.VolthaInstance)(c_items)

	for index, value := range instances {
		if c_string = C.CString(value.GetInstanceId()); c_string != nil {
			c_voltha_instance.InstanceId = c_string
		}
		if c_string = C.CString(value.GetVersion()); c_string != nil {
			c_voltha_instance.Version = c_string
		}
		if c_string = C.CString(value.GetLogLevel().String()); c_string != nil {
			c_voltha_instance.LogLevel = c_string
		}
		c_voltha_instance.Health = _proto_to_c_HealthStatus(value.GetHealth())
		c_voltha_instance.Adapters = _proto_to_c_Adapters(value.GetAdapters())
		c_voltha_instance.LogicalDevices = _proto_to_c_LogicalDevices(value.GetLogicalDevices())
		c_voltha_instance.Devices = _proto_to_c_Devices(value.GetDevices())
		c_voltha_instance.DeviceTypes = _proto_to_c_DeviceTypes(value.GetDeviceTypes())
		c_voltha_instance.DeviceGroups = _proto_to_c_DeviceGroups(value.GetDeviceGroups())
		c_voltha_instance.AlarmFilters = _proto_to_c_AlarmFilters(value.GetAlarmFilters())

		c_array[index] = c_voltha_instance
	}

	result.items = (*C.VolthaInstance)(unsafe.Pointer(c_array))

	return result
}
func _proto_to_c_Devices(instances []*pb_device.Device) C.DeviceArray {
	var result C.DeviceArray
	var c_string *C.char
	var c_device_instance C.Device
	defer C.free(unsafe.Pointer(c_string))

	sizeof := unsafe.Sizeof(c_device_instance)
	count := len(instances)
	result.size = C.int(count)

	c_items := C.malloc(C.size_t(result.size) * C.size_t(sizeof))
	defer C.free(unsafe.Pointer(c_items))

	c_array := (*[1<<30 - 1]C.Device)(c_items)

	for index, value := range instances {
		c_array[index] = _proto_to_c_Device(value)
	}

	result.items = (*C.Device)(unsafe.Pointer(c_array))

	return result
}
func _proto_to_c_Voltha(voltha *pb.Voltha) C.Voltha {
	var result C.Voltha
	var c_string *C.char
	defer C.free(unsafe.Pointer(c_string))

	if c_string = C.CString(voltha.GetVersion()); c_string != nil {
		result.Version = c_string
	}
	if c_string = C.CString(voltha.GetLogLevel().String()); c_string != nil {
		result.LogLevel = c_string
	}

	result.Instances = _proto_to_c_VolthaInstances(voltha.GetInstances())
	result.Adapters = _proto_to_c_Adapters(voltha.GetAdapters())
	result.LogicalDevices = _proto_to_c_LogicalDevices(voltha.GetLogicalDevices())
	result.Devices = _proto_to_c_Devices(voltha.GetDevices())
	result.DeviceGroups = _proto_to_c_DeviceGroups(voltha.GetDeviceGroups())

	return result
}

func _proto_to_c_Address(device *pb_device.Device) C.isDevice_Address {
	var address C.isDevice_Address
	var c_string *C.char
	defer C.free(unsafe.Pointer(c_string))

	switch device.GetAddress().(type) {
	case *pb_device.Device_MacAddress:
		address.Type = C.MAC
		c_string = C.CString(device.GetMacAddress())
		address.Value = c_string
	case *pb_device.Device_Ipv4Address:
		address.Type = C.IPV4
		c_string = C.CString(device.GetIpv4Address())
		address.Value = c_string
	case *pb_device.Device_Ipv6Address:
		address.Type = C.IPV6
		c_string = C.CString(device.GetIpv6Address())
		address.Value = c_string
	case *pb_device.Device_HostAndPort:
		address.Type = C.HOST_AND_PORT
		c_string = C.CString(device.GetHostAndPort())
		address.Value = c_string
	}
	return address
}

func _proto_to_c_Device(device *pb_device.Device) C.Device {
	var result C.Device
	var c_string *C.char
	defer C.free(unsafe.Pointer(c_string))

	if c_string = C.CString(device.GetId()); c_string != nil {
		result.Id = c_string
	}
	if c_string = C.CString(device.GetType()); c_string != nil {
		result.Type = c_string
	}
	if device.GetRoot() {
		result.Root = C.int(1)
	} else {
		result.Root = C.int(0)
	}
	if c_string = C.CString(device.GetParentId()); c_string != nil {
		result.ParentId = c_string
	}

	result.ParentPortNo = C.uint32_t(device.GetParentPortNo())

	if c_string = C.CString(device.GetVendor()); c_string != nil {
		result.Vendor = c_string
	}
	if c_string = C.CString(device.GetModel()); c_string != nil {
		result.Model = c_string
	}
	if c_string = C.CString(device.GetHardwareVersion()); c_string != nil {
		result.HardwareVersion = c_string
	}
	if c_string = C.CString(device.GetFirmwareVersion()); c_string != nil {
		result.FirmwareVersion = c_string
	}
	if c_string = C.CString(device.GetSoftwareVersion()); c_string != nil {
		result.SoftwareVersion = c_string
	}
	if c_string = C.CString(device.GetSerialNumber()); c_string != nil {
		result.SerialNumber = c_string
	}
	if c_string = C.CString(device.GetAdapter()); c_string != nil {
		result.Adapter = c_string
	}

	result.Vlan = C.uint32_t(device.GetVlan())
	result.ProxyAddress = _proto_to_c_ProxyAddress(device.GetProxyAddress())

	if c_string = C.CString(device.GetAdminState().String()); c_string != nil {
		result.AdminState = c_string
	}
	if c_string = C.CString(device.GetOperStatus().String()); c_string != nil {
		result.OperStatus = c_string
	}
	if c_string = C.CString(device.GetReason()); c_string != nil {
		result.Reason = c_string
	}
	if c_string = C.CString(device.GetConnectStatus().String()); c_string != nil {
		result.ConnectStatus = c_string
	}

	result.Custom = _proto_to_c_Custom(device.GetCustom())
	result.Ports = _proto_to_c_Ports(device.GetPorts())
	result.Flows = _proto_to_c_Flows(device.GetFlows())
	result.FlowGroups = _proto_to_c_FlowGroups(device.GetFlowGroups())
	result.PmConfigs = _proto_to_c_PmConfigs(device.GetPmConfigs())
	result.Address = _proto_to_c_Address(device)

	return result
}

// ---------------------------------------------------------
// Exported methods accessible through the shared library
// ---------------------------------------------------------

//export GetHealthStatus
func GetHealthStatus() C.HealthStatus {
	var output *pb_health.HealthStatus
	var err error

	if output, err = HealthClient.GetHealthStatus(context.Background(), &empty.Empty{}); output == nil || err != nil {
		log.Fatalf("Failed to retrieve health status: %s", err.Error())
	}

	return _proto_to_c_HealthStatus(output)
}

//export GetVoltha
func GetVoltha() C.Voltha {
	var output *pb.Voltha
	var err error
	if output, err = VolthaGlobalClient.GetVoltha(context.Background(), &empty.Empty{}); output == nil || err != nil {
		log.Fatalf("Failed to retrieve voltha information: %s", err.Error())
	}

	return _proto_to_c_Voltha(output)
}

//export ListDevices
func ListDevices() C.DeviceArray {
	var output *pb_device.Devices
	var err error
	if output, err = VolthaGlobalClient.ListDevices(context.Background(), &empty.Empty{});
		output == nil || err != nil {
		log.Fatalf("Failed to retrieve voltha information: %s", err.Error())
	}

	return _proto_to_c_Devices(output.Items)
}

//export ListVolthaInstances
func ListVolthaInstances() *C.char {
	return nil
}

//export ListLogicalDevices
func ListLogicalDevices() *C.char {
	return nil
}

//export GetLogicalDevice
func GetLogicalDevice(input *C.char) *C.char {
	return nil
}

//export ListLogicalDevicePorts
func ListLogicalDevicePorts(input *C.char) *C.char {
	return nil
}

//export ListLogicalDeviceFlows
func ListLogicalDeviceFlows(input *C.char) *C.char {
	return nil
}

//export CreateDevice
func CreateDevice(input C.Device) C.Device {
	log.Printf("Incoming C Device - type:%v, address_type: %v, address_value:%s",
		C.GoString(input.Type),
		C.int(input.Address.Type),
		C.GoString(input.Address.Value),
	)

	device := _c_to_proto_Address(input.Address)
	device.Type = C.GoString(input.Type)

	var output *pb_device.Device
	var err error

	if output, err = VolthaGlobalClient.CreateDevice(context.Background(), device);
		output == nil || err != nil {
		log.Fatalf("Failed to create device: %s", err.Error())
	}

	return _proto_to_c_Device(output)
}

// Debugging code
func TestSerialize() {
	var object C.Device

	object.Type = C.CString("simulated_olt")
	object.Address.Type = 3
	object.Address.Value = C.CString("172.16.1.233:123")

	//xmlObject, _ := xml.Marshal(object)
	//
	//log.Printf("object: %+v", string(xmlObject))

	CreateDevice(object)
}

func main() {
	// We need the main function to make possible
	// CGO compiler to compile the package as C shared library
	//TestSerialize()
}
