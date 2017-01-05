#!/usr/bin/env python
#
# Copyright 2017 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import structlog
from netconf.nc_rpc.rpc import Rpc
import netconf.nc_common.error as ncerror
from twisted.internet.defer import inlineCallbacks, returnValue
import dicttoxml

log = structlog.get_logger()


class Get(Rpc):
    def __init__(self, request, request_xml, grpc_client, session, capabilities):
        super(Get, self).__init__(request, request_xml, grpc_client, session)
        self._validate_parameters()

    @inlineCallbacks
    def execute(self):
        if self.rpc_response.is_error:
            returnValue(self.rpc_response)

        log.info('get-request', session=self.session.session_id,
                 request=self.request)

        rpc = self.get_voltha_rpc(self.request)
        if not rpc:
            log.info('unsupported-request', request=self.request)
            self.rpc_response.is_error = True
            self.rpc_response.node = ncerror.BadMsg(self.request)
            return

        # Invoke voltha via the grpc client
        res_dict = yield self.grpc_client.invoke_voltha_api(rpc)

        # convert dict to xml
        xml = dicttoxml.dicttoxml(res_dict, attr_type=True)
        log.info('voltha-info', res=res_dict, xml=xml)

        root_elem = self.get_root_element(xml)

        # Build the yang response
        self.rpc_response.node = self.rpc_response.build_yang_response(
            root_elem, self.request)
        self.rpc_response.is_error = False

        returnValue(self.rpc_response)

    def _validate_parameters(self):
        log.info('validate-parameters', session=self.session.session_id)
        # Validate the GET command
        if self.request:
            try:
                if self.request['command'] != 'get':
                    self.rpc_response.is_error = True
                    self.rpc_response.node = ncerror.BadMsg('No GET in get '
                                                            'request')

                if self.request.has_key('filter'):
                    if not self.request.has_key('class'):
                        self.rpc_response.is_error = True
                        self.rpc_response.node = ncerror.BadMsg(
                            'Missing filter sub-element')

            except Exception as e:
                self.rpc_response.is_error = True
                self.rpc_response.node = ncerror.BadMsg(self.request)
                return

    def get_voltha_rpc(self, request):
        if request.has_key('class'):
            rpcs = self.rpc_request_mapping.get(request['class'])
            if rpcs is None:
                return None
            for rpc in rpcs:
                if request.has_key('subclass'):
                    # search first for subclass
                    if rpc['subclass'] and request['subclass'] == rpc[
                        'subclass']:
                        return rpc['rpc']

            # If we are here then no subclass exists.  Just return the rpc
            # associated with theNone subclass
            for rpc in rpcs:
                if rpc['subclass'] is None:
                    return rpc['rpc']

        return None

    # Supported Get Methods
    rpc_request_mapping = {
        'Voltha': [
            {'subclass': None,
             'rpc': 'VolthaGlobalService-GetVoltha'
             }],
        'VolthaInstance': [
            {'subclass': None,
             'rpc': 'VolthaLocalService-GetVolthaInstance'
             },
            {'subclass': 'health',
             'rpc': 'VolthaLocalService-GetHealth'
             },
            {'subclass': 'adapters',
             'rpc': 'VolthaLocalService-ListAdapters'
             },
            {'subclass': 'logical_devices',
             'rpc': 'VolthaLocalService-ListLogicalDevices'
             },
            {'subclass': 'devices',
             'rpc': 'VolthaLocalService-ListDevices'
             },
            {'subclass': 'device_types',
             'rpc': 'VolthaLocalService-ListDeviceTypes'
             },
            {'subclass': 'device_groups',
             'rpc': 'VolthaLocalService-ListDeviceGroups'
             },
        ],
        'VolthaInstances': [
            {'subclass': None,
             'rpc': 'VolthaGlobalService-ListVolthaInstances'
             }],
    }
