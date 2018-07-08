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
/*
 * This is automatically generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */

#include <stdlib.h>
#include <sys/inotify.h>
#include <libxml/tree.h>
#include <libxml/xmlsave.h>
#include <libxml/xmlwriter.h>
#include <libnetconf_xml.h>
#include <voltha-netconf-model.h>
#include <voltha.h>
#include <string.h>


/* transAPI version which must be compatible with libnetconf */
int transapi_version = 6;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int config_modified = 0;

/*
 * Determines the callbacks order.
 * Set this variable before compilation and DO NOT modify it in runtime.
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF
 */
const TRANSAPI_CLBCKS_ORDER_TYPE callbacks_order = TRANSAPI_CLBCKS_ORDER_DEFAULT;

/* Do not modify or set! This variable is set by libnetconf to announce edit-config's error-option
Feel free to use it to distinguish module behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed, all successful callbacks executed till
                         failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not executed, but previous successful callbacks are
                         executed again with previous configuration data to roll it back.
 */
NC_EDIT_ERROPT_TYPE erropt = NC_EDIT_ERROPT_NOTSET;

/**
 * @brief Initialize plugin after loaded and before any other functions are called.

 * This function should not apply any configuration data to the controlled device. If no
 * running is returned (it stays *NULL), complete startup configuration is consequently
 * applied via module callbacks. When a running configuration is returned, libnetconf
 * then applies (via module's callbacks) only the startup configuration data that
 * differ from the returned running configuration data.

 * Please note, that copying startup data to the running is performed only after the
 * libnetconf's system-wide close - see nc_close() function documentation for more
 * information.

 * @param[out] running	Current configuration of managed device.

 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int transapi_init(xmlDocPtr *running) {
	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void transapi_close(void) {
	return;
}

/**
 * @brief Retrieve state data from device and return them as XML document
 *
 * @param model	Device data model. libxml2 xmlDocPtr.
 * @param running	Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err  Double pointer to error structure. Fill error when some occurs.
 * @return State data as libxml2 xmlDocPtr or NULL in case of error.
 */
xmlDocPtr get_state_data(xmlDocPtr model, xmlDocPtr running, struct nc_err **err) {
	return(NULL);
}
/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
struct ns_pair namespace_mapping[] = {{NULL, NULL}};

/*
 * CONFIGURATION callbacks
 * Here follows set of callback functions run every time some change in associated part of running datastore occurs.
 * You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
 */

/*
 * Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
 * It is used by libnetconf library to decide which callbacks will be run.
 * DO NOT alter this structure
 */
struct transapi_data_callbacks clbks =  {
	.callbacks_count = 0,
	.data = NULL,
	.callbacks = {
	}
};

/**
 * @brief Get a node from the RPC input. The first found node is returned, so if traversing lists,
 * call repeatedly with result->next as the node argument.
 *
 * @param name	Name of the node to be retrieved.
 * @param node	List of nodes that will be searched.
 * @return Pointer to the matching node or NULL
 */
xmlNodePtr get_rpc_node(const char *name, const xmlNodePtr node) {
	xmlNodePtr ret = NULL;

	for (ret = node; ret != NULL; ret = ret->next) {
		if (xmlStrEqual(BAD_CAST name, ret->name)) {
			break;
		}
	}

	return ret;
}

void walk_nodes(const xmlNodePtr node) {
	xmlNodePtr ret = NULL;

    /*
    walk through the document
    what to do with nodes ... pass to a channel?
    to construct a map at the other end?

    */
	for (ret = node; ret != NULL; ret = ret->next) {
	    if (xmlNodeIsText(ret)) {
    	    nc_verb_verbose("content : %s", (char*)xmlNodeGetContent(ret));
	    } else {
	        nc_verb_verbose("name : %s", ret->name);
        }
	    if (ret->children != NULL) {
	        walk_nodes(ret->children);
	    }
	}
}

/*
 * RPC callbacks
 * Here follows set of callback functions run every time RPC specific for this device arrives.
 * You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
 * Every function takes an libxml2 list of inputs as an argument.
 * If input was not set in RPC message argument is set to NULL. To retrieve each argument, preferably use get_rpc_node().
 */

/*
 * Local service functions
 */

nc_reply *rpc_VolthaLocalService_GetVolthaInstance(xmlNodePtr input) {
    return NULL;
}
nc_reply *rpc_VolthaLocalService_GetHealth(xmlNodePtr input) {
    HealthStatus health;
    health = (HealthStatus) GetHealthStatus();

    char* data;
    data = (char*) TranslateHealthStatus(health);

    return nc_reply_data(data);
}
nc_reply *rpc_VolthaLocalService_ListAdapters(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListLogicalDevices(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_GetLogicalDevice(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListLogicalDevicePorts(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListLogicalDeviceFlows(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_UpdateLogicalDeviceFlowTable(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListLogicalDeviceFlowGroups(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_UpdateLogicalDeviceFlowGroupTable(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListDevices(xmlNodePtr input) {
    DeviceArray devices;
    devices = (DeviceArray) ListDevices();

    char* data;
    data = (char*) TranslateDevices(devices);

    return nc_reply_data(data);
}
nc_reply *rpc_VolthaLocalService_GetDevice(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_CreateDevice(xmlNodePtr input) {
	Device d;
	xmlNodePtr ret = NULL;

    if ((ret = get_rpc_node("type", input)) != NULL) {
        d.Type = (char*)xmlNodeGetContent(ret);
    }

    if ((ret = get_rpc_node("host_and_port", input)) != NULL) {
        d.Address.Type = (int)HOST_AND_PORT;
        d.Address.Value = (char*)xmlNodeGetContent(ret);
    } else if ((ret = get_rpc_node("mac_address", input)) != NULL) {
        d.Address.Type = (int)MAC;
        d.Address.Value = (char*)xmlNodeGetContent(ret);
    } else if ((ret = get_rpc_node("ipv4_address", input)) != NULL) {
        d.Address.Type = (int)IPV4;
        d.Address.Value = (char*)xmlNodeGetContent(ret);
    } else if ((ret = get_rpc_node("ipv6_address", input)) != NULL) {
        d.Address.Type = (int)IPV6;
        d.Address.Value = (char*)xmlNodeGetContent(ret);
    }

    Device d_created;
	nc_verb_verbose("Issuing call to create");
    d_created = (Device) CreateDevice(d);
	nc_verb_verbose("Created device");

    char* data;
    data = (char*) TranslateDevice(d_created);

    return nc_reply_data((char*)data);
}
nc_reply *rpc_VolthaLocalService_EnableDevice(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_DisableDevice(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_RebootDevice(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_DeleteDevice(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListDevicePorts(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListDevicePmConfigs(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_UpdateDevicePmConfigs(xmlNodePtr input) {
    return NULL;
}
nc_reply *rpc_VolthaLocalService_ListDeviceFlows(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListDeviceFlowGroups(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListDeviceTypes(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_GetDeviceType(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListDeviceGroups(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_GetDeviceGroup(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_StreamPacketsOut(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ReceivePacketsIn(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ReceiveChangeEvents(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_CreateAlarmFilter(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_GetAlarmFilter(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_UpdateAlarmFilter(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_DeleteAlarmFilter(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaLocalService_ListAlarmFilters(xmlNodePtr input) {
	return NULL;
}

/*
 * Global service functions
 *
 */
nc_reply *rpc_HealthService_GetHealthStatus(xmlNodePtr input) {
    return rpc_VolthaLocalService_GetHealth(input);
}
nc_reply *rpc_VolthaGlobalService_GetVoltha(xmlNodePtr input) {
    Voltha voltha;
    voltha = (Voltha) GetVoltha();

    nc_verb_verbose("version : %s", (char*)voltha.Version);
    nc_verb_verbose("log_level : %s", (char*)voltha.LogLevel);

    char* data;
    data = (char*) TranslateVoltha(voltha);

    return nc_reply_data(data);
}
nc_reply *rpc_VolthaGlobalService_ListVolthaInstances(xmlNodePtr input) {
	return NULL;
}
nc_reply *rpc_VolthaGlobalService_GetVolthaInstance(xmlNodePtr input) {
	return rpc_VolthaLocalService_GetVolthaInstance(input);
}
nc_reply *rpc_VolthaGlobalService_ListLogicalDevices(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListLogicalDevices(input);
}
nc_reply *rpc_VolthaGlobalService_GetLogicalDevice(xmlNodePtr input) {
	return rpc_VolthaLocalService_GetLogicalDevice(input);
}
nc_reply *rpc_VolthaGlobalService_ListLogicalDevicePorts(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListLogicalDevicePorts(input);
}
nc_reply *rpc_VolthaGlobalService_ListLogicalDeviceFlows(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListLogicalDeviceFlows(input);
}
nc_reply *rpc_VolthaGlobalService_UpdateLogicalDeviceFlowTable(xmlNodePtr input) {
	return rpc_VolthaLocalService_UpdateLogicalDeviceFlowTable(input);
}
nc_reply *rpc_VolthaGlobalService_ListLogicalDeviceFlowGroups(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListLogicalDeviceFlowGroups(input);
}
nc_reply *rpc_VolthaGlobalService_UpdateLogicalDeviceFlowGroupTable(xmlNodePtr input) {
	return rpc_VolthaLocalService_UpdateLogicalDeviceFlowGroupTable(input);
}
nc_reply *rpc_VolthaGlobalService_ListDevices(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListDevices(input);
}
nc_reply *rpc_VolthaGlobalService_GetDevice(xmlNodePtr input) {
	return rpc_VolthaLocalService_GetDevice(input);
}
nc_reply *rpc_VolthaGlobalService_CreateDevice(xmlNodePtr input) {
    return rpc_VolthaLocalService_CreateDevice(input);
}
nc_reply *rpc_VolthaGlobalService_EnableDevice(xmlNodePtr input) {
	return rpc_VolthaLocalService_EnableDevice(input);
}
nc_reply *rpc_VolthaGlobalService_DisableDevice(xmlNodePtr input) {
	return rpc_VolthaLocalService_DisableDevice(input);
}
nc_reply *rpc_VolthaGlobalService_RebootDevice(xmlNodePtr input) {
	return rpc_VolthaLocalService_RebootDevice(input);
}
nc_reply *rpc_VolthaGlobalService_DeleteDevice(xmlNodePtr input) {
	return rpc_VolthaLocalService_DeleteDevice(input);
}
nc_reply *rpc_VolthaGlobalService_ListDevicePorts(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListDevicePorts(input);
}
nc_reply *rpc_VolthaGlobalService_ListDevicePmConfigs(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListDevicePmConfigs(input);
}
nc_reply *rpc_VolthaGlobalService_UpdateDevicePmConfigs(xmlNodePtr input) {
    return rpc_VolthaLocalService_UpdateDevicePmConfigs(input);
}
nc_reply *rpc_VolthaGlobalService_ListDeviceFlows(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListDeviceFlows(input);
}
nc_reply *rpc_VolthaGlobalService_ListDeviceFlowGroups(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListDeviceFlowGroups(input);
}
nc_reply *rpc_VolthaGlobalService_ListDeviceTypes(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListDeviceTypes(input);
}
nc_reply *rpc_VolthaGlobalService_GetDeviceType(xmlNodePtr input) {
	return rpc_VolthaLocalService_GetDeviceType(input);
}
nc_reply *rpc_VolthaGlobalService_ListDeviceGroups(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListDeviceGroups(input);
}
nc_reply *rpc_VolthaGlobalService_GetDeviceGroup(xmlNodePtr input) {
	return rpc_VolthaLocalService_GetDeviceGroup(input);
}
nc_reply *rpc_VolthaGlobalService_CreateAlarmFilter(xmlNodePtr input) {
	return rpc_VolthaLocalService_CreateAlarmFilter(input);
}
nc_reply *rpc_VolthaGlobalService_GetAlarmFilter(xmlNodePtr input) {
	return rpc_VolthaLocalService_GetAlarmFilter(input);
}
nc_reply *rpc_VolthaGlobalService_UpdateAlarmFilter(xmlNodePtr input) {
	return rpc_VolthaLocalService_UpdateAlarmFilter(input);
}
nc_reply *rpc_VolthaGlobalService_DeleteAlarmFilter(xmlNodePtr input) {
	return rpc_VolthaLocalService_DeleteAlarmFilter(input);
}
nc_reply *rpc_VolthaGlobalService_ListAlarmFilters(xmlNodePtr input) {
	return rpc_VolthaLocalService_ListAlarmFilters(input);
}

/*
 * Structure transapi_rpc_callbacks provides mapping between callbacks and RPC messages.
 * It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
 * DO NOT alter this structure
 */
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 66,
	.callbacks = {
		{.name="HealthService-GetHealthStatus", .func=rpc_HealthService_GetHealthStatus},
		{.name="VolthaGlobalService-GetVoltha", .func=rpc_VolthaGlobalService_GetVoltha},
		{.name="VolthaGlobalService-ListVolthaInstances", .func=rpc_VolthaGlobalService_ListVolthaInstances},
		{.name="VolthaGlobalService-GetVolthaInstance", .func=rpc_VolthaGlobalService_GetVolthaInstance},
		{.name="VolthaGlobalService-ListLogicalDevices", .func=rpc_VolthaGlobalService_ListLogicalDevices},
		{.name="VolthaGlobalService-GetLogicalDevice", .func=rpc_VolthaGlobalService_GetLogicalDevice},
		{.name="VolthaGlobalService-ListLogicalDevicePorts", .func=rpc_VolthaGlobalService_ListLogicalDevicePorts},
		{.name="VolthaGlobalService-ListLogicalDeviceFlows", .func=rpc_VolthaGlobalService_ListLogicalDeviceFlows},
		{.name="VolthaGlobalService-UpdateLogicalDeviceFlowTable", .func=rpc_VolthaGlobalService_UpdateLogicalDeviceFlowTable},
		{.name="VolthaGlobalService-ListLogicalDeviceFlowGroups", .func=rpc_VolthaGlobalService_ListLogicalDeviceFlowGroups},
		{.name="VolthaGlobalService-UpdateLogicalDeviceFlowGroupTable", .func=rpc_VolthaGlobalService_UpdateLogicalDeviceFlowGroupTable},
		{.name="VolthaGlobalService-ListDevices", .func=rpc_VolthaGlobalService_ListDevices},
		{.name="VolthaGlobalService-GetDevice", .func=rpc_VolthaGlobalService_GetDevice},
		{.name="VolthaGlobalService-CreateDevice", .func=rpc_VolthaGlobalService_CreateDevice},
		{.name="VolthaGlobalService-EnableDevice", .func=rpc_VolthaGlobalService_EnableDevice},
		{.name="VolthaGlobalService-DisableDevice", .func=rpc_VolthaGlobalService_DisableDevice},
		{.name="VolthaGlobalService-RebootDevice", .func=rpc_VolthaGlobalService_RebootDevice},
		{.name="VolthaGlobalService-DeleteDevice", .func=rpc_VolthaGlobalService_DeleteDevice},
		{.name="VolthaGlobalService-ListDevicePorts", .func=rpc_VolthaGlobalService_ListDevicePorts},
		{.name="VolthaGlobalService-ListDevicePmConfigs", .func=rpc_VolthaGlobalService_ListDevicePmConfigs},
		{.name="VolthaGlobalService-UpdateDevicePmConfigs", .func=rpc_VolthaGlobalService_UpdateDevicePmConfigs},
		{.name="VolthaGlobalService-ListDeviceFlows", .func=rpc_VolthaGlobalService_ListDeviceFlows},
		{.name="VolthaGlobalService-ListDeviceFlowGroups", .func=rpc_VolthaGlobalService_ListDeviceFlowGroups},
		{.name="VolthaGlobalService-ListDeviceTypes", .func=rpc_VolthaGlobalService_ListDeviceTypes},
		{.name="VolthaGlobalService-GetDeviceType", .func=rpc_VolthaGlobalService_GetDeviceType},
		{.name="VolthaGlobalService-ListDeviceGroups", .func=rpc_VolthaGlobalService_ListDeviceGroups},
		{.name="VolthaGlobalService-GetDeviceGroup", .func=rpc_VolthaGlobalService_GetDeviceGroup},
		{.name="VolthaGlobalService-CreateAlarmFilter", .func=rpc_VolthaGlobalService_CreateAlarmFilter},
		{.name="VolthaGlobalService-GetAlarmFilter", .func=rpc_VolthaGlobalService_GetAlarmFilter},
		{.name="VolthaGlobalService-UpdateAlarmFilter", .func=rpc_VolthaGlobalService_UpdateAlarmFilter},
		{.name="VolthaGlobalService-DeleteAlarmFilter", .func=rpc_VolthaGlobalService_DeleteAlarmFilter},
		{.name="VolthaGlobalService-ListAlarmFilters", .func=rpc_VolthaGlobalService_ListAlarmFilters},
		{.name="VolthaLocalService-GetVolthaInstance", .func=rpc_VolthaLocalService_GetVolthaInstance},
		{.name="VolthaLocalService-GetHealth", .func=rpc_VolthaLocalService_GetHealth},
		{.name="VolthaLocalService-ListAdapters", .func=rpc_VolthaLocalService_ListAdapters},
		{.name="VolthaLocalService-ListLogicalDevices", .func=rpc_VolthaLocalService_ListLogicalDevices},
		{.name="VolthaLocalService-GetLogicalDevice", .func=rpc_VolthaLocalService_GetLogicalDevice},
		{.name="VolthaLocalService-ListLogicalDevicePorts", .func=rpc_VolthaLocalService_ListLogicalDevicePorts},
		{.name="VolthaLocalService-ListLogicalDeviceFlows", .func=rpc_VolthaLocalService_ListLogicalDeviceFlows},
		{.name="VolthaLocalService-UpdateLogicalDeviceFlowTable", .func=rpc_VolthaLocalService_UpdateLogicalDeviceFlowTable},
		{.name="VolthaLocalService-ListLogicalDeviceFlowGroups", .func=rpc_VolthaLocalService_ListLogicalDeviceFlowGroups},
		{.name="VolthaLocalService-UpdateLogicalDeviceFlowGroupTable", .func=rpc_VolthaLocalService_UpdateLogicalDeviceFlowGroupTable},
		{.name="VolthaLocalService-ListDevices", .func=rpc_VolthaLocalService_ListDevices},
		{.name="VolthaLocalService-GetDevice", .func=rpc_VolthaLocalService_GetDevice},
		{.name="VolthaLocalService-CreateDevice", .func=rpc_VolthaLocalService_CreateDevice},
		{.name="VolthaLocalService-EnableDevice", .func=rpc_VolthaLocalService_EnableDevice},
		{.name="VolthaLocalService-DisableDevice", .func=rpc_VolthaLocalService_DisableDevice},
		{.name="VolthaLocalService-RebootDevice", .func=rpc_VolthaLocalService_RebootDevice},
		{.name="VolthaLocalService-DeleteDevice", .func=rpc_VolthaLocalService_DeleteDevice},
		{.name="VolthaLocalService-ListDevicePorts", .func=rpc_VolthaLocalService_ListDevicePorts},
		{.name="VolthaLocalService-ListDevicePmConfigs", .func=rpc_VolthaLocalService_ListDevicePmConfigs},
		{.name="VolthaLocalService-UpdateDevicePmConfigs", .func=rpc_VolthaLocalService_UpdateDevicePmConfigs},
		{.name="VolthaLocalService-ListDeviceFlows", .func=rpc_VolthaLocalService_ListDeviceFlows},
		{.name="VolthaLocalService-ListDeviceFlowGroups", .func=rpc_VolthaLocalService_ListDeviceFlowGroups},
		{.name="VolthaLocalService-ListDeviceTypes", .func=rpc_VolthaLocalService_ListDeviceTypes},
		{.name="VolthaLocalService-GetDeviceType", .func=rpc_VolthaLocalService_GetDeviceType},
		{.name="VolthaLocalService-ListDeviceGroups", .func=rpc_VolthaLocalService_ListDeviceGroups},
		{.name="VolthaLocalService-GetDeviceGroup", .func=rpc_VolthaLocalService_GetDeviceGroup},
		{.name="VolthaLocalService-StreamPacketsOut", .func=rpc_VolthaLocalService_StreamPacketsOut},
		{.name="VolthaLocalService-ReceivePacketsIn", .func=rpc_VolthaLocalService_ReceivePacketsIn},
		{.name="VolthaLocalService-ReceiveChangeEvents", .func=rpc_VolthaLocalService_ReceiveChangeEvents},
		{.name="VolthaLocalService-CreateAlarmFilter", .func=rpc_VolthaLocalService_CreateAlarmFilter},
		{.name="VolthaLocalService-GetAlarmFilter", .func=rpc_VolthaLocalService_GetAlarmFilter},
		{.name="VolthaLocalService-UpdateAlarmFilter", .func=rpc_VolthaLocalService_UpdateAlarmFilter},
		{.name="VolthaLocalService-DeleteAlarmFilter", .func=rpc_VolthaLocalService_DeleteAlarmFilter},
		{.name="VolthaLocalService-ListAlarmFilters", .func=rpc_VolthaLocalService_ListAlarmFilters}
	}
};

/*
 * Structure transapi_file_callbacks provides mapping between specific files
 * (e.g. configuration file in /etc/) and the callback function executed when
 * the file is modified.
 * The structure is empty by default. Add items, as in example, as you need.
 *
 * Example:
 * int example_callback(const char *filepath, xmlDocPtr *edit_config, int *exec) {
 *     // do the job with changed file content
 *     // if needed, set edit_config parameter to the edit-config data to be applied
 *     // if needed, set exec to 1 to perform consequent transapi callbacks
 *     return 0;
 * }
 *
 * struct transapi_file_callbacks file_clbks = {
 *     .callbacks_count = 1,
 *     .callbacks = {
 *         {.path = "/etc/my_cfg_file", .func = example_callback}
 *     }
 * }
 */
struct transapi_file_callbacks file_clbks = {
	.callbacks_count = 0,
	.callbacks = {{NULL}}
};

