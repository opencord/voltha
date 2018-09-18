#
# Copyright 2018 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import shlex
from argparse import ArgumentParser, ArgumentError

import structlog
from twisted.internet.defer import inlineCallbacks, returnValue

from common.pon_resource_manager.resource_manager import PONResourceManager
from voltha.registry import registry


# Used to parse extra arguments to OpenOlt adapter from the NBI
class OpenOltArgumentParser(ArgumentParser):
    # Must override the exit command to prevent it from
    # calling sys.exit().  Return exception instead.
    def exit(self, status=0, message=None):
        raise Exception(message)


class OpenOltResourceMgr(object):

    GEMPORT_IDS = "gemport_ids"
    ALLOC_IDS = "alloc_ids"

    def __init__(self, device_id, host_and_port, extra_args, device_info):
        self.log = structlog.get_logger(id=device_id,
                                        ip=host_and_port)
        self.device_id = device_id
        self.host_and_port = host_and_port
        self.extra_args = extra_args
        self.device_info = device_info
        # Below dictionary maintains a map of tuple (pon_intf_id, onu_id)
        # to list of gemports and alloc_ids.
        # Note: This is a stateful information and will be lost across
        # VOLTHA reboots. When adapter is containerized, this information
        # should be backed up in an external K/V store.
        '''
        Example:
        {
            (pon_intf_id_1, onu_id_1): {
                    "gemport_ids": [1024,1025],
                    "alloc_ids"  : [1024]
            },
            (pon_intf_id_1, onu_id_2): {
                    "gemport_ids": [1026],
                    "alloc_ids"  : [1025]
            }
        }
        '''
        self.pon_intf_id_onu_id_to_resource_map = dict()
        self.pon_intf_gemport_to_onu_id_map = dict()
        self.resource_mgr = self.\
            _parse_extra_args_and_init_resource_manager_class()
        # Flag to indicate whether information fetched from device should
        # be used to intialize PON Resource Ranges
        self.use_device_info = False

    def _parse_extra_args_and_init_resource_manager_class(self):
        self.args = registry('main').get_args()

        # KV store's IP Address and PORT
        host, port = '127.0.0.1', 8500
        if self.args.backend == 'etcd':
            host, port = self.args.etcd.split(':', 1)
        elif self.args.backend == 'consul':
            host, port = self.args.consul.split(':', 1)

        if self.extra_args and len(self.extra_args) > 0:
            parser = OpenOltArgumentParser(add_help=False)
            parser.add_argument('--openolt_variant', '-o', action='store',
                                choices=['default', 'asfvolt16'],
                                default='default')
            try:
                args = parser.parse_args(shlex.split(self.extra_args))
                self.log.debug('parsing-extra-arguments', args=args)

                try:
                    resource_manager = PONResourceManager(
                        self.device_info.technology,
                        args.openolt_variant,
                        self.device_id, self.args.backend,
                        host, port
                    )
                except Exception as e:
                    raise Exception(e)

            except ArgumentError as e:
                raise Exception('invalid-arguments: {}'.format(e.message))

            except Exception as e:
                raise Exception(
                    'option-parsing-error: {}'.format(e.message))
        else:
            try:
                # OLT Vendor type not available, use device information
                # to initialize PON resource ranges.
                self.use_device_info = True

                resource_manager = PONResourceManager(
                    self.device_info.technology,
                    self.device_info.vendor,
                    self.device_id, self.args.backend,
                    host, port
                )
            except Exception as e:
                raise Exception(e)

        return resource_manager

    def init_resource_store(self, pon_intf_onu_id):
        # Initialize the map to store the (pon_intf_id, onu_id) to gemport
        # list and alloc_id list
        if pon_intf_onu_id not in \
                self.pon_intf_id_onu_id_to_resource_map.keys():
            self.pon_intf_id_onu_id_to_resource_map[pon_intf_onu_id] = dict()
            self.pon_intf_id_onu_id_to_resource_map[pon_intf_onu_id] \
                [OpenOltResourceMgr.GEMPORT_IDS] = list()
            self.pon_intf_id_onu_id_to_resource_map[pon_intf_onu_id] \
                [OpenOltResourceMgr.ALLOC_IDS] = list()

    @inlineCallbacks
    def get_resource_id(self, pon_intf_id, resource_type, num_of_id=1):
        resource = yield self.resource_mgr.get_resource_id(
            pon_intf_id, resource_type, num_of_id)
        returnValue(resource)

    @inlineCallbacks
    def free_resource_id(self, pon_intf_id, resource_type, release_content):
        result = yield self.resource_mgr.free_resource_id(
            pon_intf_id, resource_type, release_content)
        returnValue(result)

    @inlineCallbacks
    def get_alloc_id(self, pon_intf_onu_id):
        # Derive the pon_intf from the pon_intf_onu_id tuple
        pon_intf = pon_intf_onu_id[0]
        alloc_id = None

        # Since we support only one alloc_id for the ONU at the moment,
        # return the first alloc_id in the list, if available, for that
        # ONU.
        if len(self.pon_intf_id_onu_id_to_resource_map[pon_intf_onu_id] \
                       [OpenOltResourceMgr.ALLOC_IDS]) > 0:
            alloc_id = self.pon_intf_id_onu_id_to_resource_map[
                pon_intf_onu_id][OpenOltResourceMgr.ALLOC_IDS][0]
            returnValue(alloc_id)

        # get_alloc_id returns a list of alloc_id.
        alloc_id_list = yield self.resource_mgr.get_resource_id(
            pon_intf_id=pon_intf,
            resource_type=PONResourceManager.ALLOC_ID,
            num_of_id=1
        )
        if alloc_id_list and len(alloc_id_list) == 0:
            self.log.error("no-alloc-id-available")
            returnValue(alloc_id)

        # store the alloc id list per (pon_intf_id, onu_id) tuple
        self.pon_intf_id_onu_id_to_resource_map[pon_intf_onu_id] \
            [OpenOltResourceMgr.ALLOC_IDS].extend(alloc_id_list)

        # Since we request only one alloc id, we refer the 0th
        # index
        alloc_id = alloc_id_list[0]

        returnValue(alloc_id)

    @inlineCallbacks
    def get_gemport_id(self, pon_intf_onu_id):
        # Derive the pon_intf and onu_id from the pon_intf_onu_id tuple
        pon_intf = pon_intf_onu_id[0]
        onu_id = pon_intf_onu_id[1]
        gemport = None

        if len(self.pon_intf_id_onu_id_to_resource_map[pon_intf_onu_id] \
                       [OpenOltResourceMgr.GEMPORT_IDS]) > 0:
            # Since we support only one gemport_id on the ONU at the moment,
            # return the first gemport_id in the list, if available, for that
            # ONU.
            gemport = self.pon_intf_id_onu_id_to_resource_map[pon_intf_onu_id] \
                [OpenOltResourceMgr.GEMPORT_IDS][0]
            returnValue(gemport)

        # get_gem_id returns a list of gem_id.
        gemport_id_list = yield self.resource_mgr.get_resource_id(
            pon_intf_id=pon_intf,
            resource_type=PONResourceManager.GEMPORT_ID,
            num_of_id=1
        )

        if gemport_id_list and len(gemport_id_list) == 0:
            self.log.error("no-gemport-id-available")
            returnValue(gemport)

        # store the gem port id list per (pon_intf_id, onu_id) tuple
        self.pon_intf_id_onu_id_to_resource_map[pon_intf_onu_id] \
            [OpenOltResourceMgr.GEMPORT_IDS].extend(gemport_id_list)

        # We currently use only one gemport
        gemport = gemport_id_list[0]

        pon_intf_gemport = (pon_intf, gemport)
        # This information is used when packet_indication is received and
        # we need to derive the ONU Id for which the packet arrived based
        # on the pon_intf and gemport available in the packet_indication
        self.pon_intf_gemport_to_onu_id_map[pon_intf_gemport] = onu_id

        returnValue(gemport)

    def free_pon_resources_for_onu(self, pon_intf_id, onu_id):
        # Frees Alloc Ids and Gemport Ids from Resource Manager for
        # a given onu on a particular pon port

        pon_intf_id_onu_id = (pon_intf_id, onu_id)
        alloc_ids = \
            self.pon_intf_id_onu_id_to_resource_map[pon_intf_id_onu_id] \
                [OpenOltResourceMgr.ALLOC_IDS]
        gemport_ids = \
            self.pon_intf_id_onu_id_to_resource_map[pon_intf_id_onu_id] \
                [OpenOltResourceMgr.GEMPORT_IDS]
        self.resource_mgr.free_resource_id(pon_intf_id,
                                               PONResourceManager.ONU_ID,
                                               onu_id)
        self.resource_mgr.free_resource_id(pon_intf_id,
                                               PONResourceManager.ALLOC_ID,
                                               alloc_ids)
        self.resource_mgr.free_resource_id(pon_intf_id,
                                               PONResourceManager.GEMPORT_ID,
                                               gemport_ids)

        # We need to clear the mapping of (pon_intf_id, gemport_id) to onu_id
        for gemport_id in gemport_ids:
            del self.pon_intf_gemport_to_onu_id_map[(pon_intf_id, gemport_id)]

    @inlineCallbacks
    def initialize_device_resource_range_and_pool(self):
        if not self.use_device_info:
            status = yield self.resource_mgr.init_resource_ranges_from_kv_store()
            if not status:
                self.log.error("failed-to-load-resource-range-from-kv-store")
                # When we have failed to read the PON Resource ranges from KV
                # store, use the information fetched from device.
                self.use_device_info = True

        if self.use_device_info:
            self.log.info("using-device-info-to-init-pon-resource-ranges")
            self.resource_mgr.init_default_pon_resource_ranges(
                self.device_info.onu_id_start,
                self.device_info.onu_id_end,
                self.device_info.alloc_id_start,
                self.device_info.alloc_id_end,
                self.device_info.gemport_id_start,
                self.device_info.gemport_id_end,
                self.device_info.pon_ports
            )

        # After we have initialized resource ranges, initialize the
        # resource pools accordingly.
        self.resource_mgr.init_device_resource_pool()

    def clear_device_resource_pool(self):
        self.resource_mgr.clear_device_resource_pool()
