# Copyright 2017-present Adtran, Inc.
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

import json
import random

import structlog

from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue
#

from voltha.extensions.alarms.onu.onu_los_alarm import OnuLosAlarm
from voltha.protos.common_pb2 import AdminState
from voltha.protos.device_pb2 import Port

class PonPort(object):
    """

    This is a highly reduced version taken from the adtran pon_port.
    TODO: Extend for use in the openolt adapter set.
    """
    MAX_ONUS_SUPPORTED = 256
    DEFAULT_ENABLED = False
    MAX_DEPLOYMENT_RANGE = 25000    # Meters (OLT-PB maximum)

    _MCAST_ONU_ID = 253
    _MCAST_ALLOC_BASE = 0x500

    _SUPPORTED_ACTIVATION_METHODS = ['autodiscovery']    # , 'autoactivate']
    _SUPPORTED_AUTHENTICATION_METHODS = ['serial-number']

    def __init__(self, **kwargs):

        # super(PonPort, self).__init__(parent, **kwargs)

        assert 'pon-id' in kwargs, 'PON ID not found'


        self._pon_id = kwargs['pon-id']
        self._device_id = kwargs['device_id']
        self._intf_id = kwargs['intf_id']
        self.log = structlog.get_logger(device_id=self._device_id, pon_id=self._pon_id)
        self._port_no = kwargs['port_no']
        self._port_id = 0
        # self._name = 'xpon 0/{}'.format(self._pon_id+1)
        self._label = 'pon-{}'.format(self._pon_id)

        self._onus = {}         # serial_number-base64 -> ONU  (allowed list)
        self._onu_by_id = {}    # onu-id -> ONU

        """
        Statistics  taken from nni_port
        self.intf_id = 0  #handled by getter
        self.port_no = 0  #handled by getter
        self.port_id = 0  #handled by getter  
        
        Note:  In the current implementation of the kpis coming from the BAL the stats are the
        samne model for NNI and PON.
        
        TODO:   Integrate additional kpis for the PON and other southbound port objecgts.      
        
        """

        self.rx_bytes = 0
        self.rx_packets = 0
        self.rx_mcast_packets = 0
        self.rx_bcast_packets = 0
        self.rx_error_packets = 0
        self.tx_bytes = 0
        self.tx_packets = 0
        self.tx_ucast_packets = 0
        self.tx_mcast_packets = 0
        self.tx_bcast_packets = 0
        self.tx_error_packets = 0
        return

    def __str__(self):
        return "PonPort-{}: Admin: {}, Oper: {}, OLT: {}".format(self._label,
                                                                 self._admin_state,
                                                                 self._oper_status,
                                                                 self.olt)


    @property
    def intf_id(self):
        return self._intf_id

    @intf_id.setter
    def intf_id(self, value):
        self._intf_id = value

    @property
    def pon_id(self):
        return self._pon_id
    @pon_id.setter
    def pon_id(self, value):
        self._pon_id = value

    @property
    def port_no(self):
        return self._port_no
    @port_no.setter
    def port_no(self, value):
        self._port_no = value

    @property
    def port_id(self):
        return self._port_id
    @intf_id.setter
    def port_id(self, value):
        self._port_id = value

    @property
    def onus(self):
        """
        Get a set of all ONUs.  While the set is immutable, do not use this method
        to get a collection that you will iterate through that my yield the CPU
        such as inline callback.  ONUs may be deleted at any time and they will
        set some references to other objects to NULL during the 'delete' call.
        Instead, get a list of ONU-IDs and iterate on these and call the 'onu'
        method below (which will return 'None' if the ONU has been deleted.

        :return: (frozenset) collection of ONU objects on this PON
        """
        return frozenset(self._onus.values())

    @property
    def onu_ids(self):
        return frozenset(self._onu_by_id.keys())

    def onu(self, onu_id):
        return self._onu_by_id.get(onu_id)




