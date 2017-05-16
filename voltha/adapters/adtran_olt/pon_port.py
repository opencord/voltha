#
# Copyright 2017-present Adtran, Inc.
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
import json
import pprint
import random

import os
import structlog
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue

from adtran_olt_handler import AdtranOltHandler
from codec.olt_config import OltConfig
from onu import Onu
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Device
from voltha.protos.device_pb2 import Port

log = structlog.get_logger()


class PonPort(object):
    """
    A class similar to the 'Port' class in the VOLTHA
    
    TODO: Merge this with the Port class or cleanup where possible
          so we do not duplicate fields/properties/methods
    """
    MAX_ONUS_SUPPORTED = 256
    DEFAULT_ENABLED = False

    def __init__(self, pon_index, port_no, parent, admin_state=AdminState.UNKNOWN, label=None):
        # TODO: Weed out those properties supported by common 'Port' object
        assert admin_state != AdminState.UNKNOWN
        self.parent = parent
        self._pon_index = pon_index
        self._port_no = port_no
        self.label = label or 'PON-{}'.format(pon_index)
        self.admin_state = admin_state
        self.oper_status = OperStatus.ACTIVE  # TODO: Need to discover
        self.startup = None
        self.onu_discovery = None
        self.port = None
        self.no_onu_discover_tick = 5.0  # TODO: Decrease to 1 or 2 later
        self.discovery_tick = 20.0
        self.discovered_onus = []  # List of serial numbers
        self.onus = {}  # serial_number -> ONU  (allowed list)
        self.next_onu_id = Onu.MIN_ONU_ID

    def __del__(self):
        # self.stop()
        pass

    def __str__(self):
        return "PonPort-{}: Admin: {}, Oper: {}, parent: {}".format(self.label,
                                                                    self.admin_state,
                                                                    self.oper_status,
                                                                    self.parent)

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        if self.port is None:
            self.port = Port(port_no=self.port_number,
                             label=self.label,
                             type=Port.PON_OLT,
                             admin_state=self.admin_state,
                             oper_status=self.oper_status)
        return self.port

    @property
    def port_number(self):
        return self._port_no

    @property
    def pon_id(self):
        return self._pon_index

    def get_logical_port(self):
        """
        Get the VOLTHA logical port for this port
        :return: VOLTHA logical port or None if not supported
        """
        return None

    @inlineCallbacks
    def start(self):
        """
        Start/enable this PON and start ONU discover
        :return: (deferred)
        """
        log.info('Starting {}'.format(self.label))

        """
        Here is where I will start to bring up a PON port and discover an ONT

        Note: For some reason, you cannot chain the FEC enables with the pon enable below?
        """
        try:
            self.startup = self.set_pon_config("enabled", True)
            yield self.startup

        except Exception, e:
            log.exception("enabled failed: {}".format(str(e)))
            raise

        try:
            self.startup = self.set_pon_config("downstream-fec-enable", True)
            yield self.startup

        except Exception, e:
            log.exception("downstream FEC enable failed: {}".format(str(e)))
            raise

        try:
            self.startup = self.set_pon_config("upstream-fec-enable", True)
            results = yield self.startup

        except Exception, e:
            log.exception("upstream FEC enable failed: {}".format(str(e)))
            raise

        log.debug('ONU Startup complete: results: {}'.
                  format(pprint.PrettyPrinter().pformat(results)))

        if isinstance(results, dict) and results.get('enabled', False):
            self.admin_state = AdminState.ENABLED
            self.oper_status = OperStatus.ACTIVE  # TODO: is this correct, how do we tell GRPC

            # Begin to ONU discovery.  Once a second if no ONUs found and once every 20
            #       seconds after one or more ONUs found on the PON
            self.onu_discovery = reactor.callLater(3, self.discover_onus)
            returnValue(self.onu_discovery)

        else:
            # Startup failed. Could be due to object creation with an invalid initial admin_status
            #                 state.  May want to schedule a start to occur again if this happens
            self.admin_state = AdminState.DISABLED
            self.oper_status = OperStatus.UNKNOWN
            raise NotImplementedError('TODO: Support of PON startup failure not yet supported')

    @inlineCallbacks
    def stop(self):
        log.info('Stopping {}'.format(self.label))
        d, self.startup = self.startup, None
        if d is not None:
            d.cancel()

        d, self.onu_discovery = self.onu_discovery, None
        if d is not None:
            d.cancel()

        self.reset(False)
        self.admin_state = AdminState.DISABLED
        self.oper_status = OperStatus.UNKNOWN
        # TODO: How do we reflect this into VOLTHA?

    @inlineCallbacks
    def reset(self):
        log.info('Reset {}'.format(self.label))

        if self.admin_state != self.parent.initial_port_state:
            try:
                enable = self.parent.initial_port_state == AdminState.ENABLED
                yield self.set_pon_config("enabled", enable)

                # TODO: Move to 'set_pon_config' method and also make sure GRPC/Port is ok
                self.admin_state = AdminState.ENABLED if enable else AdminState.DISABLE

            except Exception as e:
                log.exception('Reset of PON {} to initial state failed'.
                              format(self.pon_id), e=e)
                raise

        if self.admin_state == AdminState.ENABLED and self.parent.initial_onu_state == AdminState.DISABLED:
            try:
                # Walk the provisioned ONU list and disable any exiting ONUs
                results = yield self.get_onu_config()

                if isinstance(results, list) and len(results) > 0:
                    onu_configs = OltConfig.Pon.Onu.decode(results)
                    for onu_id in onu_configs.iterkeys():
                        try:
                            yield self.delete_onu(onu_id)

                        except Exception as e:
                            log.exception('Delete of ONU {} on PON {} failed'.
                                          format(onu_id, self.pon_id), e=e)
                            pass  # Non-fatal

            except Exception as e:
                log.exception('Failed to get current ONU config for PON {}'.
                              format(self.pon_id), e=e)
                raise

    def get_pon_config(self):
        uri = AdtranOltHandler.GPON_PON_CONFIG_URI.format(self.pon_id)
        name = 'pon-get-config-{}'.format(self.pon_id)
        return self.parent.rest_client.request('GET', uri, name=name)

    def get_onu_config(self, onu_id=None):
        uri = AdtranOltHandler.GPON_PON_ONU_CONFIG_URI.format(self.pon_id)
        if onu_id is not None:
            uri += '={}'.format(onu_id)
        name = 'pon-get-onu_config-{}-{}'.format(self.pon_id, onu_id)
        return self.parent.rest_client.request('GET', uri, name=name)

    def set_pon_config(self, leaf, value):
        data = json.dumps({leaf: value})
        uri = AdtranOltHandler.GPON_PON_CONFIG_URI.format(self.pon_id)
        name = 'pon-set-config-{}-{}-{}'.format(self.pon_id, leaf, str(value))
        return self.parent.rest_client.request('PATCH', uri, data=data, name=name)

    def discover_onus(self):
        log.debug("Initiating discover of ONU/ONTs on PON {}".format(self.pon_id))

        if self.admin_state == AdminState.ENABLED:
            data = json.dumps({'pon-id': self.pon_id})
            uri = AdtranOltHandler.GPON_PON_DISCOVER_ONU
            name = 'pon-discover-onu-{}'.format(self.pon_id)
            self.startup = self.parent.rest_client.request('POST', uri, data, name=name)

            self.startup.addBoth(self.onu_discovery_init_complete)

    def onu_discovery_init_complete(self, _):
        """
        This method is called after the REST POST to request ONU discovery is
        completed.  The results (body) of the post is always empty / 204 NO CONTENT
        """
        log.debug('PON {} ONU Discovery requested'.format(self.pon_id))

        # Reschedule

        delay = self.no_onu_discover_tick if len(self.onus) == 0 else self.discovery_tick
        delay += random.uniform(-delay / 10, delay / 10)

        self.onu_discovery = reactor.callLater(delay, self.discover_onus)

    def process_status_poll(self, status):
        """
        Process PON status poll request
        
        :param status: (OltState.Pon object) results from RESTCONF GET
        """
        log.debug('process_status_poll: PON {}: {}{}'.format(self.pon_id,
                                                             os.linesep,
                                                             status))
        if self.admin_state != AdminState.ENABLED:
            return

        # Process the ONU list in for this PON, may have previously provisioned ones there
        # were discovered on an earlier boot

        new = self._process_status_onu_list(status.onus)

        for onu_id in new:
            # self.add_new_onu(serial_number, status)
            log.info('Found ONU {} in status list'.format(onu_id))
            raise NotImplementedError('TODO: Adding ONUs from existing ONU (status list) not supported')

        # Get new/missing from the discovered ONU leaf

        new, missing = self._process_status_onu_discovered_list(status.discovered_onu)

        # TODO: Do something useful
        if len(missing):
            log.info('Missing ONUs are: {}'.format(missing))

        for serial_number in new:
            reactor.callLater(0, self.add_onu, serial_number, status)

        # Process discovered ONU list

        # TODO: Process LOS list
        # TODO: Process status
        pass

    def _process_status_onu_list(self, onus):
        """
        Look for new or missing ONUs

        :param onus: (dict) Set of known ONUs
        """
        log.debug('Processing ONU list: {}'.format(onus))

        my_onu_ids = frozenset([o.onu_id for o in self.onus.itervalues()])
        discovered_onus = frozenset(onus.keys())

        new_onus_ids = discovered_onus - my_onu_ids
        missing_onus_ids = my_onu_ids - discovered_onus

        new = {o: v for o, v in onus.iteritems() if o in new_onus_ids}
        missing_onus = {o: v for o, v in onus.iteritems() if o in missing_onus_ids}

        return new  # , missing_onus        # TODO: Support ONU removal

    def _process_status_onu_discovered_list(self, discovered_onus):
        """
        Look for new or missing ONUs
        
        :param discovered_onus: (frozenset) Set of ONUs currently discovered
        """
        log.debug('Processing discovered ONU list: {}'.format(discovered_onus))

        my_onus = frozenset(self.onus.keys())

        new_onus = discovered_onus - my_onus
        missing_onus = my_onus - discovered_onus

        return new_onus, missing_onus

    @inlineCallbacks
    def add_onu(self, serial_number, status):
        log.info('Add ONU: {}'.format(serial_number))

        if serial_number not in status.onus:
            # Newly found and not enabled ONU, enable it now if not at max

            if len(self.onus) < self.MAX_ONUS_SUPPORTED:
                # TODO: For now, always allow any ONU

                if serial_number not in self.onus:
                    onu = Onu(serial_number, self)

                    try:
                        yield onu.create(True)

                        self.on_new_onu_discovered(onu)
                        self.onus[serial_number] = onu

                    except Exception as e:
                        log.exception('Exception during add_onu, pon: {}, onu: {}'.
                                      format(self.pon_id, onu.onu_id), e=e)
                else:
                    log.info('TODO: Code this')

            else:
                log.warning('Maximum number of ONUs already provisioned on PON {}'.
                            format(self.pon_id))
        else:
            # ONU has been enabled
            pass

    def on_new_onu_discovered(self, onu):
        """
        Called when a new ONU is discovered and VOLTHA device adapter needs to be informed
        :param onu: 
        :return: 
        """
        olt = self.parent
        adapter = olt.adapter_agent

        proxy = Device.ProxyAddress(device_id=olt.device_id,
                                    channel_id=self.port_number,
                                    onu_id=onu.onu_id)

        adapter.child_device_detected(parent_device_id=olt.device_id,
                                      parent_port_no=self.port_number,
                                      child_device_type=onu.vendor_device,
                                      proxy_address=proxy)

    def get_next_onu_id(self):
        used_ids = [onu.onu_id for onu in self.onus]

        while True:
            onu_id = self.next_onu_id
            self.next_onu_id += 1

            if self.next_onu_id > Onu.MAX_ONU_ID:
                self.next_onu_id = Onu.MIN_ONU_ID

            if onu_id not in used_ids:
                return onu_id

    def delete_onu(self, onu_id):
        uri = AdtranOltHandler.GPON_PON_ONU_CONFIG_URI.format(self.pon_id)
        uri += '={}'.format(onu_id)
        name = 'pon-delete-onu-{}-{}'.format(self.pon_id, onu_id)

        # TODO: Need removal from VOLTHA child_device method

        return self.parent.rest_client.request('DELETE', uri, name=name)
