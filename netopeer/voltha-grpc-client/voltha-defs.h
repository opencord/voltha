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

#ifndef VOLTHA_DEFS
#define VOLTHA_DEFS

#include <stdint.h>

typedef enum {
    OUTPUT = 0,
    MPLS_TTL = 1,
    PUSH = 2,
    POP_MPLS = 3,
    GROUP = 4,
    NW_TTL = 5,
    SET_FIELD = 6,
    EXPERIMENTER = 7
} isOfpAction_ActionEnum;

typedef enum {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
} LogLevelEnum;

typedef enum {
    OFPIT_INVALID = 0,
    OFPIT_GOTO_TABLE = 1,
    OFPIT_WRITE_METADATA = 2,
    OFPIT_WRITE_ACTIONS = 3,
    OFPIT_APPLY_ACTIONS = 4,
    OFPIT_CLEAR_ACTIONS = 5,
    OFPIT_METER = 6,
    OFPIT_EXPERIMENTER = 7
} isOfpInstruction_DataEnum;

typedef enum {
    OFB_FIELD = 0,
    EXPERIMENTER_FIELD = 1
} isOfpOxmField_FieldEnum;

typedef enum {
    MAC = 0,
    IPV4 = 1,
    IPV6 = 2,
    HOST_AND_PORT = 3
} isDevice_AddressEnum;

typedef enum {
    HEALTHY = 0,
    OVERLOADED = 1,
    DYING = 1
} HealthStatusEnum;

typedef struct {
	char* State;
} HealthStatus;

typedef struct {
	char* MfrDesc;
	char* HwDesc;
	char* SwDesc;
	char* SerialNum;
	char* DpDesc;
} OfpDesc;

typedef struct {
	uint32_t NBuffers;
	uint32_t NTables;
	uint32_t AuxiliaryId;
	uint32_t Capabilities;
	uint64_t DatapathId;
} OfpSwitchFeatures;

typedef struct {
	char* Value;
	int Type;
} isOfpOxmField_Field;

typedef struct {
	int32_t OxmClass;
	isOfpOxmField_Field Field;
} OfpOxmField;

typedef struct {
	OfpOxmField* items;
	int size;
} OfpOxmFieldArray;

typedef struct {
	int32_t Type;
	OfpOxmFieldArray OxmFields;
} OfpMatch;

typedef struct {
	int Type;
	char* Value;
} isOfpAction_Action;

typedef struct {
	int32_t Type;
	isOfpAction_Action Action;
} OfpAction;

typedef struct {
	int Type;
	char* Value;
} isOfpInstruction_Data;

typedef struct {
	isOfpInstruction_Data Data;
	uint32_t Type;
} OfpInstruction;

typedef struct {
	OfpInstruction* items;
	int size;
} OfpInstructionArray;

typedef struct {
	uint64_t PacketCount;
	uint64_t ByteCount;
	OfpMatch* Match;
	uint64_t Id;
	uint32_t DurationSec;
	uint32_t Priority;
	uint32_t HardTimeout;
	uint32_t Flags;
	uint32_t TableId;
	uint32_t DurationNsec;
	uint32_t IdleTimeout;
	uint64_t Cookie;
	OfpInstructionArray Instructions;
} OfpFlowStats;

typedef struct {
	OfpFlowStats* items;
	int size;
} OfpFlowStatsArray;

typedef struct {
	OfpFlowStatsArray Items;
} Flows;

typedef struct {
	OfpAction* items;
	int size;
} OfpActionArray;

typedef struct {
	OfpActionArray Actions;
	uint32_t Weight;
	uint32_t WatchPort;
	uint32_t WatchGroup;
} OfpBucket;

typedef struct {
	OfpBucket* items;
	int size;
} OfpBucketArray;

typedef struct {
	int32_t Type;
	uint32_t GroupId;
	OfpBucketArray Buckets;
} OfpGroupDesc;

typedef struct {
	uint64_t PacketCount;
	uint64_t ByteCount;
} OfpBucketCounter;

typedef struct {
	OfpBucketCounter* items;
	int size;
} OfpBucketCounterArray;

typedef struct {
	uint32_t RefCount;
	uint64_t PacketCount;
	uint64_t ByteCount;
	uint32_t DurationSec;
	uint32_t DurationNsec;
	OfpBucketCounterArray BucketStats;
	uint32_t GroupId;
} OfpGroupStats;

typedef struct {
	OfpGroupDesc* Desc;
	OfpGroupStats* Stats;
} OfpGroupEntry;

typedef struct {
	OfpGroupEntry* items;
	int size;
} OfpGroupEntryArray;

typedef struct {
	OfpGroupEntryArray Items;
} FlowGroups;

typedef struct {
	uint32_t SampleFreq;
	char* Name;
	int32_t Type;
	int Enabled;
} PmConfig;

typedef struct {
	PmConfig* items;
	int size;
} PmConfigArray;

typedef struct {
	char* GroupName;
	uint32_t GroupFreq;
	int Enabled;
	PmConfigArray Metrics;
} PmGroupConfig;

typedef struct {
	PmGroupConfig* items;
	int size;
} PmGroupConfigArray;

typedef struct {
	uint32_t items;
	int size;
} uint32Array;

typedef struct {
	uint32Array HwAddr;
	uint32_t State;
	uint32_t Curr;
	uint32_t MaxSpeed;
	uint32_t PortNo;
	char* Name;
	uint32_t Config;
	uint32_t Advertised;
	uint32_t Supported;
	uint32_t Peer;
	uint32_t CurrSpeed;
} OfpPort;

typedef struct {
	char* Value;
	int Type;
} isDevice_Address;

typedef struct {
	char* DeviceId;
	uint32_t ChannelId;
	uint32_t OnuId;
	uint32_t OnuSessionId;
} Device_ProxyAddress;

typedef struct {
	char** items;
	int size;
} stringArray;

typedef struct {
	uint8_t* items;
	int size;
} uint8Array;

typedef struct {
	uint8Array Value;
	char* TypeUrl;
} Any;

typedef struct {
	int32_t LogLevel;
	Any* AdditionalConfig;
} AdapterConfig;

typedef struct {
	AdapterConfig* Config;
	Any* AdditionalDescription;
	stringArray LogicalDeviceIds;
	char* Id;
	char* Vendor;
	char* Version;
} Adapter;

typedef struct {
	int32_t Key;
	char* Value;
} AlarmFilterRule;

typedef struct {
	AlarmFilterRule* items;
	int size;
} AlarmFilterRuleArray;

typedef struct {
	char* Id;
	AlarmFilterRuleArray Rules;
} AlarmFilter;

typedef struct {
	AlarmFilter* items;
	int size;
} AlarmFilterArray;

typedef struct {
	char* Id;
	OfpPort* OfpPort;
	char* DeviceId;
	uint32_t DevicePortNo;
	int RootPort;
} LogicalPort;

typedef struct {
	LogicalPort* items;
	int size;
} LogicalPortArray;

typedef struct {
	FlowGroups* FlowGroups;
	char* Id;
	uint64_t DatapathId;
	OfpDesc* Desc;
	OfpSwitchFeatures* SwitchFeatures;
	char* RootDeviceId;
	LogicalPortArray Ports;
	Flows* Flows;
} LogicalDevice;

typedef struct {
	LogicalDevice* items;
	int size;
} LogicalDeviceArray;

typedef struct {
	uint32_t PortNo;
	char* DeviceId;
} Port_PeerPort;

typedef struct {
	Port_PeerPort* items;
	int size;
} Port_PeerPortArray;

typedef struct {
	uint32_t PortNo;
	char* Label;
	int32_t Type;
	int32_t AdminState;
	int32_t OperStatus;
	char* DeviceId;
	Port_PeerPortArray Peers;
} Port;

typedef struct {
	Port* items;
	int size;
} PortArray;

typedef struct {
	uint32_t DefaultFreq;
	int Grouped;
	int FreqOverride;
	PmGroupConfigArray Groups;
	PmConfigArray Metrics;
	char* Id;
} PmConfigs;

typedef struct {
	char* Id;
	char* Adapter;
	int AcceptsBulkFlowUpdate;
	int AcceptsAddRemoveFlowUpdates;
} DeviceType;

typedef struct {
	DeviceType* items;
	int size;
} DeviceTypeArray;

typedef struct {
	char* Reason;
	char* ConnectStatus;
	FlowGroups* FlowGroups;
	char* Id;
	char* Model;
	Device_ProxyAddress* ProxyAddress;
	char* OperStatus;
	uint32_t ParentPortNo;
	char* HardwareVersion;
	Flows* Flows;
	PmConfigs* PmConfigs;
	char* AdminState;
	char* Type;
	char* ParentId;
	char* Vendor;
	char* SerialNumber;
	uint32_t Vlan;
	isDevice_Address Address;
	Any* Custom;
	PortArray Ports;
	int Root;
	char* FirmwareVersion;
	char* SoftwareVersion;
	char* Adapter;
} Device;

typedef struct {
	Device* items;
	int size;
} DeviceArray;

typedef struct {
	char* Id;
	LogicalDeviceArray LogicalDevices;
	DeviceArray Devices;
} DeviceGroup;

typedef struct {
	DeviceGroup* items;
	int size;
} DeviceGroupArray;

typedef struct {
	Adapter* items;
	int size;
} AdapterArray;

typedef struct {
	AlarmFilterArray AlarmFilters;
	char* InstanceId;
	HealthStatus Health;
	AdapterArray Adapters;
	LogicalDeviceArray LogicalDevices;
	DeviceGroupArray DeviceGroups;
	char* Version;
	char* LogLevel;
	DeviceArray Devices;
	DeviceTypeArray DeviceTypes;
} VolthaInstance;

typedef struct {
	VolthaInstance* items;
	int size;
} VolthaInstanceArray;

typedef struct {
	char* Version;
	char* LogLevel;
	VolthaInstanceArray Instances;
	AdapterArray Adapters;
	LogicalDeviceArray LogicalDevices;
	DeviceArray Devices;
	DeviceGroupArray DeviceGroups;
} Voltha;

#endif
