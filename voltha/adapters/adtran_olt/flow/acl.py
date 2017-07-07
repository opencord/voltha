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
import structlog

import voltha.core.flow_decomposer as fd

log = structlog.get_logger()

_acl_list = {}      # Key -> Name: List of encoded EVCs


class ACL(object):
    """
    Class to wrap Trap-to-Controller functionality
    """

    def __init__(self, flow_entry):
        self._installed = False
        self._status_message = None
        self._parent = flow_entry           # FlowEntry parent
        self._flow = flow_entry.flow
        self._handler = flow_entry.handler
        self._name = ACL.flow_to_name(flow_entry)

        self._valid = self._decode()

    @staticmethod
    def create(flow_entry):
        pass                    # TODO: Start here Thursday

    @staticmethod
    def flow_to_name(flow_entry):
        return 'ACL-{}-{}'.format(flow_entry.handler.device_id, flow_entry.flow.id)

    @property
    def valid(self):
        return self._valid

    @property
    def installed(self):
        return self._installed

    @property
    def status(self):
        return self._status_message

    def install(self):
        if not self._installed:
            if self._name in _acl_list:
                self._status_message = "ACL '{}' already is installed".format(self.name)
                raise Exception(self._status_message)   # TODO: A unique exception type would work here

            raise NotImplemented('TODO: Implement this')

            self._installed = True
            _acl_list[self.name] = self
            pass

        return self._installed

    def remove(self):
        if self._installed:
            raise NotImplemented('TODO: Implement this')

            self._installed = False
            _acl_list.pop(self._name)
            pass

        return not self._installed

    def enable(self):
        if not self._enabled:
            raise NotImplemented("TODO: Implement this")
            self._enabled = False

    def disable(self):
        if self._enabled:
            raise NotImplemented("TODO: Implement this")
            self._enabled = True

    def _decode(self):
        """
        Examine flow rules and extract appropriate settings for both this EVC
        and creates any EVC-Maps required.
        """
        self._name = ACL.flow_to_name(self._flow, self._handler)

        # Determine this flow's type

        status = self._decode_traffic_selector() and self._decode_traffic_treatment()

        if status:
            pass    # TODO

            if status:
                pass     # TODO
            else:
                pass     # TODO

        return status

    def _decode_traffic_selector(self):
        """
        Extract EVC related traffic selection settings
        """
        in_port = fd.get_in_port(self._flow)
        assert in_port is not None

        log.debug('InPort: {}', in_port)

        for field in fd.get_ofb_fields(self._flow):
            log.debug('Found-OFB-field', field=field)

        for action in fd.get_actions(self._flow):
            log.debug('Found-Action', action=action)

        return True

    def _decode_traffic_treatment(self):
        out_port = fd.get_out_port(self._flow)

        log.debug('OutPort: {}', out_port)

        for field in fd.get_ofb_fields(self._flow):
            log.debug('Found-OFB-field', field=field)

        for action in fd.get_actions(self._flow):
            log.debug('Found-Action', action=action)

        return True

    # BULK operations

    @staticmethod
    def enable_all():
        raise NotImplemented("TODO: Implement this")

    @staticmethod
    def disable_all():
        raise NotImplemented("TODO: Implement this")

    @staticmethod
    def remove_all():
        """
        Remove all ACLs from hardware
        """
        raise NotImplemented("TODO: Implement this")

