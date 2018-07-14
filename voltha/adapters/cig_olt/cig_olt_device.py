#
# Copyright 2017-present CIG, Inc.
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
import base64
import binascii
import json
import pprint
import random
import os
import structlog

from enum import Enum
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, succeed

from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.bbf_fiber_types_pb2 import *
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Device
from voltha.protos.device_pb2 import Port
from voltha.protos.logical_device_pb2 import *
from voltha.protos.openflow_13_pb2 import *

from voltha.protos.olt_common_pb2 import *
from voltha.protos.olt_d_pb2 import *
from voltha.protos.olt_pon_pb2 import *
from voltha.protos.olt_switch_pb2 import *
#from voltha.adapters.cig_olt.protos.olt_common_pb2 import *
#from voltha.adapters.cig_olt.protos.olt_d_pb2 import *
#from voltha.adapters.cig_olt.protos.olt_pon_pb2 import *
#from voltha.adapters.cig_olt.protos.olt_switch_pb2 import *

from cig_olt_zmq import *
from cig_olt_xpon import *

log = structlog.get_logger()

class NniPort(object):
    """
    A class similar to the 'Port' class in the VOLTHA
    
    TODO: Merge this with the Port class or cleanup where possible
          so we do not duplicate fields/properties/methods
    """

    def __init__(self, nni_port, parent_id):
        self.log = structlog.get_logger(device_id=parent_id)
        self._parent_id = parent_id
        self._port_no = nni_port.port_no
        self._mac_address = nni_port.mac_address
        if self._mac_address is None:
            self._mac_address = "11:22:33:44:55:66"

        if nni_port.port_type == OLT_NNI_PORT_TYPE_10G:
            self._ofp_capabilities = OFPPF_10GB_FD | OFPPF_FIBER
            self._current_speed = OFPPF_10GB_FD
            self._max_speed = OFPPF_10GB_FD
        elif nni_port.port_type == OLT_NNI_PORT_TYPE_40G:
            self._ofp_capabilities = OFPPF_40GB_FD | OFPPF_FIBER
            self._current_speed = OFPPF_40GB_FD
            self._max_speed = OFPPF_40GB_FD
        elif nni_port.port_type == OLT_NNI_PORT_TYPE_100G or nni_port.port_type == OLT_NNI_PORT_TYPE_80G:
            self._ofp_capabilities = OFPPF_100GB_FD | OFPPF_FIBER
            self._current_speed = OFPPF_100GB_FD
            self._max_speed = OFPPF_100GB_FD
        else:
            return error

        self._ofp_state = OFPPS_LIVE
        
        self.startup = None
        self._port = None
        self._logical_port = None

        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE
        log.info('Creating NNI Port {}'.format(self._port_no))

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        self.log.info('get nni gort', self._port_no)
        if self._port is None:
            self._port = Port(port_no=self._port_no,    \
                              label='NNI port',         \
                              type=Port.ETHERNET_NNI,   \
                              admin_state=self._admin_state,    \
                              oper_status=self._oper_status)
        return self._port
    
    def get_logical_port(self):
        """
        Get the VOLTHA logical port for this port
        :return: VOLTHA logical port or None if not supported
        """
        if self._logical_port is None:
            openflow_port = ofp_port(port_no=self._port_no, \
                                     hw_addr=mac_str_to_tuple(self._mac_address),   \
                                     name='nni' + str(self._port_no),   \
                                     config=0,  \
                                     state=self._ofp_state, \
                                     curr=self._ofp_capabilities,   \
                                     advertised=self._ofp_capabilities, \
                                     peer=self._ofp_capabilities,   \
                                     curr_speed=self._current_speed,    \
                                     max_speed=self._max_speed)
    
            self._logical_port = LogicalPort(id='nni{}'.format(self._port_no),  \
                                             ofp_port=openflow_port,    \
                                             device_id=self._parent_id, \
                                             device_port_no=self._port_no,  \
                                             root_port=True)
        return self._logical_port

    def delete(self):
        """
        Parent device is being deleted. Do not change any config but
        stop all polling
        """
        self.log.info('Deleting')
        #self.state = DELETING
        #self.cancel_deferred()

class PonPort(object):
    """
    A class similar to the 'Port' class in the VOLTHA
    
    TODO: Merge this with the Port class or cleanup where possible
          so we do not duplicate fields/properties/methods
    """
    MAX_ONUS_SUPPORTED = 1024
    DEFAULT_ENABLED = False

    #def __init__(self, port_no, parent_id):
    def __init__(self, port_no, parent):
        # TODO: Weed out those properties supported by common 'Port' object
        self.log = structlog.get_logger(device_id=parent.device_id)
        self._parent_id = parent.device_id
        self._parent = parent
        self._pon_id = port_no
        self._port_no = port_no
        self._name = 'xpon 0/{}'.format(port_no)
        self._label = 'pon-{}'.format(port_no)
        self.startup = None
        self._port = None

        self._discovery_tick = 20.0
        self._no_onu_discover_tick = self._discovery_tick / 2
        self._sync_tick = 20.0
        self._in_sync = False
        self._expedite_sync = False
        self._expedite_count = 0


        
        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE

        #self.onus = {} 
        #self._onus = {}         # serial_number-base64 -> ONU  (allowed list)
        self._onu_by_id = {}    # onu-id -> ONU

        self._deferred = None                     # General purpose
        self._discovery_deferred = None           # Specifically for ONU discovery
        self._sync_deferred = None                # For sync of PON config to hardware

        self._active_los_alarms = set()           # ONU-ID

        # xPON configuration

        self._xpon_name = None
        self._enabled = False
        self._downstream_fec_enable = False
        self._upstream_fec_enable = False
        self._deployment_range = 25000
        self._authentication_method = 'serial-number'


        log.info('Creating pon Port {}'.format(self._port_no))  

    def __del__(self):
        #self.stop()
        pass
    
    def __str__(self):
        return "PonPort-{}: Admin: {}, Oper: {}, OLT: {}".format(self._label,
                                                                 self._admin_state,
                                                                 self._oper_status,
                                                                 self._parent)
    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        self.log.info('get pon gort', self._port_no)
        if self._port is None:
            self._port = Port(    \
                port_no=100 + self._port_no,    \
                #port_no=self._port_no,    \
                label=self._label,        \
                type=Port.PON_OLT,        \
                admin_state=self._admin_state,    \
                oper_status=self._oper_status     \
            )

        return self._port

    @property
    def port_number(self):
        return self._port_no

    @property
    def name(self):
        return self._name

    @property
    def pon_id(self):
        return self._pon_id

    @property
    def olt(self):
        return self._parent

    def onu(self, onu_id):
        return self._onu_by_id.get(onu_id)
        
    #def onu_add(self, onu_id, sn):
    def onu_add(self, onu_info):

        sn = onu_info['serial-number']
        onu_id = onu_info['onu-id']
        self.log.info('Add ONU: {}'.format(sn))

        if onu_id not in self._onu_by_id:
            # Newly found and not enabled ONU, enable it now if not at max

            if len(self._onu_by_id) < self.MAX_ONUS_SUPPORTED:
                # TODO: For now, always allow any ONU to be activated

                #self.on_new_onu_discovered(onu)
                #self.onus[sn] = str(onu_id)
                self._onu_by_id[onu_id] = Onu(onu_info)
                olt = self.olt
                onu = self.onu(onu_id)
                if (olt.work_mode == OLT_MODE_AUTO) and (onu._ranging_status == 1)  and (onu._config_status == 0):
                    #add onu to oltd
                    self.onu_add_msg_send(onu)
                    onu._status_machine = 'activating'
                    
                elif (olt.work_mode == OLT_MODE_CONFIG) and (onu._config_status == 1):
                    #add onu to oltd
                    self.onu_add_msg_send(onu)
                    onu._status_machine = 'activating'
                else:
                    pass
            else:
                self.log.warning('Maximum number of ONUs already provisioned')
        else:
            # ONU has been enabled
            pass


    def onu_update(self, onu_info):

        if onu_info['serial-number'] is not None:
            sn = onu_info['serial-number']
            self.log.info('update ONU: {}'.format(sn))
            
        onu_id = onu_info['onu-id']
        onu = self.onu(onu_id)
        if onu is None:
            return
            
        olt = self.olt
        if olt.work_mode == OLT_MODE_AUTO:
            return
        
        if onu_info['ranging-status'] is not None:
            onu._ranging_status = onu_info['ranging-status']
                    
        if onu_info['config-status'] is not None:
            if (onu_info['config-status'] == 1) and (onu._config_status == 0):
                #add onu to oltd
                self.onu_add_msg_send(onu)
                onu._status_machine = 'activating'
                onu._config_status = onu_info['config-status']
                    
            if (onu_info['config-status'] == 0) and (onu._config_status == 1):
                self.onu_delete_msg_send(onu)
                del self._onu_by_id[onu_id]
                    
                       
        if onu_info['channel-id'] is not None:
            onu._channel_id = onu_info['channel-id']

        if onu_info['status_machine'] is not None:
            onu._status_machine = onu_info['status_machine']

        if onu_info['upstream-fec'] is not None:
            if onu._status_machine == 'activating' or onu._status_machine == 'activation_successful':
                if onu._upstream_fec != onu_info['upstream-fec']:
                    onu._upstream_fec = onu_info['upstream-fec']
                    self.onu_update_msg_send(onu)
            else :
                onu._upstream_fec = onu_info['upstream-fec']
                

    def onu_del(self, onu_id):
        self.log.info('Delete ONU: {}'.format(onu_id))

        if onu_id in self._onu_by_id:
            onu = self.onu(onu_id)
            if onu is None:
                return
            if onu._status_machine != 'init':
                self.onu_delete_msg_send(onu)
                
            del self._onu_by_id[onu_id]

        else:
            # ONU has been delete
            pass


    def onu_exist_check(self, onu_id):
        return onu_id in self._onu_by_id

    def onu_add_msg_send(self, onu):
        try:
            msg_hdr = OltMsgCommonHdr(
                type=OLT_D_ADD_ONU,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
            data=msg_hdr.SerializeToString()
            self._parent.zmq_client_async.async_send(data,1)

            olt = self.olt
            if olt.work_mode == OLT_MODE_AUTO:
                onu_add = OltDAddOnu(
                    pon_port=onu._pon_id,
                    onu_id=onu.onu_id,
                    sn=onu._serial_number_string,
                    registration_id= "",
                    fec_upstream= onu._upstream_fec,
                    authentication_method=SERIAL_NUMBER
                )
            else:
                channel_partition_name = onu._channel_partition
                cp = olt.channel_partitions.get(channel_partition_name)
                
                if cp['authentication-method'] == 'serial-number':
                    auth_method = SERIAL_NUMBER
                elif cp['authentication-method'] == 'loid':
                    auth_method = LOID
                elif cp['authentication-method'] == 'registration-id':
                    auth_method = REGISTRATION_ID
                elif cp['authentication-method'] == 'omci':
                    auth_method = OMCI
                elif cp['authentication-method'] == 'dot1x':
                    auth_method = DOT1X
                else :
                    auth_method = SERIAL_NUMBER

                #self.log.info('onu_add_msg_send cp', cp) 
                #self.log.info('onu_add_msg_send auth_method', auth_method)
                #ani = olt.ont_anis.get(onu._vani_name)
                #if ani is not None:
                    #ups_fec = ani['upstream-fec']
                #else:
                    #ups_fec = 1
                
                onu_add = OltDAddOnu(
                    pon_port=onu._pon_id,
                    onu_id=onu.onu_id,
                    sn=onu._serial_number_string,
                    registration_id= onu._registration_id,
                    #fec_upstream=ups_fec,
                    fec_upstream=onu._upstream_fec,
                    authentication_method=auth_method
                )
            data=onu_add.SerializeToString()
            self._parent.zmq_client_async.async_send(data,0)
        
        except Exception as e:
            self.log.exception('Exception during add onu', e=e)
            
    def onu_delete_msg_send(self, onu):
        try:
            msg_hdr = OltMsgCommonHdr(
                type=OLT_D_DELETE_ONU,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
            data=msg_hdr.SerializeToString()
            self._parent.zmq_client_async.async_send(data,1)
        
            onu_delete = OltDDeleteOnu(
                pon_port=onu._pon_id,
                onu_id=onu.onu_id,
                sn=onu._serial_number_string
            )
            data=onu_delete.SerializeToString()
            self._parent.zmq_client_async.async_send(data,0)
        
        except Exception as e:
            self.log.exception('Exception during delete onu', e=e)


    def onu_update_msg_send(self, onu):
        try:
            msg_hdr = OltMsgCommonHdr(
                type=OLT_D_UPDATE_ONU,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
            data=msg_hdr.SerializeToString()
            self._parent.zmq_client_async.async_send(data,1)

            olt = self.olt
            channel_partition_name = onu._channel_partition
            cp = olt.channel_partitions.get(channel_partition_name)
            
            if cp['authentication-method'] == 'serial-number':
                auth_method = SERIAL_NUMBER
            elif cp['authentication-method'] == 'loid':
                auth_method = LOID
            elif cp['authentication-method'] == 'registration-id':
                auth_method = REGISTRATION_ID
            elif cp['authentication-method'] == 'omci':
                auth_method = OMCI
            elif cp['authentication-method'] == 'dot1x':
                auth_method = DOT1X
            else :
                auth_method = SERIAL_NUMBER

            onu_update = OltDUpdateOnu(
                pon_port=onu._pon_id,
                onu_id=onu.onu_id,
                sn=onu._serial_number_string,
                registration_id= onu._registration_id,
                fec_upstream=onu._upstream_fec,
                authentication_method=auth_method
            )
            data=onu_update.SerializeToString()
            self._parent.zmq_client_async.async_send(data,0)
        
        except Exception as e:
            self.log.exception('Exception during update onu', e=e)


    def delete(self):
        """
        Parent device is being deleted. Do not change any config but
        stop all polling
        """
        self.log.info('Deleting')
        #self.state = DELETING
        #self.cancel_deferred()
        for onu in self._onu_by_id.itervalues():
            onu.delete()

        self._onu_by_id.clear()
            
class Onu(object):
    """
    Wraps an ONU
    """
    MIN_ONU_ID = 0
    MAX_ONU_ID = 253            # G.984. 0..253, 254=reserved, 255=broadcast
    BROADCAST_ONU_ID = 255
    DEFAULT_PASSWORD = ''

    def __init__(self, onu_info):
        self._onu_id = onu_info['onu-id']
        self._ranging_status = onu_info['ranging-status']
        self._config_status = onu_info['config-status']
        self._status_machine = onu_info['status_machine']
        
        if self._onu_id is None:
            raise ValueError('No ONU ID available')

        pon = onu_info['pon']
        #self._serial_number_base64 = Onu.string_to_serial_number(onu_info['serial-number'])
        self._serial_number_string = onu_info['serial-number']
        self._device_id = onu_info['device-id']
        self._password = onu_info['password']
        self._registration_id = onu_info['expected-registration-id']
        self._channel_partition = onu_info['channel-partition']
        self._vani_name = onu_info['name']
        self._upstream_fec = onu_info['upstream-fec']

        #self._upstream_channel_speed = onu_info[upstream-channel-speed]

        
        self._olt = pon.olt
        self._pon_id = pon.pon_id
        self._name = '{}@{}'.format(pon.name, self._onu_id)
        self._xpon_name = onu_info['xpon-name']
        self._gem_ports = {}                           # gem-id -> GemPort
        self._tconts = {}                              # alloc-id -> TCont
        self._onu_vid = onu_info['onu-vid']
        self._uni_ports = [onu_info['onu-vid']]
        assert len(self._uni_ports) == 1, 'Only one UNI port supported at this time'
        self._channel_id = onu_info['channel-id']
        self._enabled = onu_info['enabled']
        self._vont_ani = onu_info.get('vont-ani')
        self._rssi = -9999
        self._equalization_delay = 0
        self._fiber_length = 0
        self._valid = True          # Set false during delete/cleanup
        self._proxy_address = None

        self._include_multicast = True        # TODO: May need to add multicast on a per-ONU basis

        self._expedite_sync = False
        self._expedite_count = 0
        self._resync_flows = False
        self._sync_deferred = None     # For sync of ONT config to hardware

        # TODO: enable and upstream-channel-speed not yet supported

        self.log = structlog.get_logger(pon_id=self._pon_id, onu_id=self._onu_id)

    def __del__(self):
        # self.stop()
        pass

    def __str__(self):
        return "Onu-{}-{}, PON ID: {}".format(self._onu_id, self._serial_number_string, self._pon_id)

    @property
    def olt(self):
        return self._olt

    @property
    def pon(self):
        return self.olt.southbound_ports[self._pon_id]

    @property
    def onu_id(self):
        return self._onu_id

    @property
    def device_id(self):
        return self._device_id

    @property
    def name(self):
        return self._name

    @property
    def enabled(self):
        return self._enabled
        
    def _get_v_ont_ani(self, olt):
        onu = None
        try:
            vont_ani = olt.v_ont_anis.get(self.vont_ani)
            ch_pair = olt.channel_pairs.get(vont_ani['preferred-channel-pair'])
            ch_term = next((term for term in olt.channel_terminations.itervalues()
                            if term['channel-pair'] == ch_pair['name']), None)

            pon = olt.pon(ch_term['xgs-ponid'])
            onu = pon.onu(vont_ani['onu-id'])

        except Exception:
            pass

        return onu

    def _cancel_deferred(self):
        d, self._sync_deferred = self._sync_deferred, None

        if d is not None and not d.called:
            try:
                d.cancel()
            except Exception:
                pass

    def delete(self):
        """
        Clean up ONU (gems/tconts). ONU removal from OLT h/w done by PonPort
        :return: (deferred)
        """

        self.log.info('onu Deleting')
        self._valid = False
        self._cancel_deferred()

        self._gem_ports.clear()
        self._tconts.clear()
        self._olt = None
        self._channel_id = None


    def start(self):
        self._cancel_deferred()
        #self._sync_deferred = reactor.callLater(0, self._sync_hardware)

    def stop(self):
        self._cancel_deferred()
        #self._sync_deferred = reactor.callLater(0, self._sync_hardware)



    #@inlineCallbacks
    def add_tcont(self, tcont, reflow=False):
        """
        Creates/ a T-CONT with the given alloc-id

        :param tcont: (TCont) Object that maintains the TCONT properties
        :param reflow: (boolean) If true, force add (used during h/w resync)
        :return: (deferred)
        """

        self._tconts[tcont.alloc_id] = tcont
        log.info('add_tcont onu_status_machine:', self._status_machine)
        #log.info('add_tcont:', self._tconts[tcont.alloc_id])
        #if self._status_machine == 'activation_successful':
            #pass
            #self.tcont_add_msg_send(self._olt, self._tconts[tcont.alloc_id])
        self.tcont_add_msg_send(self._olt, tcont.alloc_id)
        

    def update_tcont(self, alloc_id, new_values):
        # TODO: If alloc-id in use by a gemport, should we deny request?
        tcont = self._tconts.get(alloc_id)

        #if tcont is None:
            #returnValue(succeed('not-found'))

        # del self._tconts[alloc_id]
        #
        # try:
        #     results = yield tcont.remove_from_hardware()
        #
        # except Exception as e:
        #     self.log.exception('delete', e=e)
        #     raise

        #returnValue(succeed('TODO: Not implemented yet'))

    #@inlineCallbacks
    def remove_tcont(self, alloc_id):
        # TODO: If alloc-id in use by a gemport, should we deny request?
        tcont = self._tconts.get(alloc_id)

        if tcont is None:
            return

        log.info('remove_tcont alloc_id:', alloc_id)
        #log.info('remove_tcont:', self._tconts[tcont.alloc_id])
        #if self._status_machine == 'activation_successful':
        self.tcont_delete_msg_send(self._olt, alloc_id)
            
        del self._tconts[alloc_id]


    def tcont_add_msg_send(self, olt, alloc_id):
        tcont = self._tconts.get(alloc_id)
        try:
            msg_hdr = OltMsgCommonHdr(
                type=OLT_PON_ADD_TCONT,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
            data=msg_hdr.SerializeToString()
            olt.zmq_client_async.async_send(data,1)
        
            tcont_add = OltPonAddTcont(
                #pon_port=tcont.pon_id,
                pon_port=self._pon_id,
                onu_id=self._onu_id,
                alloc_id=tcont.alloc_id,
                fixed_bandwidth= tcont.traffic_descriptor.fixed_bandwidth,
                assured_bandwidth= tcont.traffic_descriptor.assured_bandwidth,
                maximum_bandwidth=tcont.traffic_descriptor.maximum_bandwidth
            )
            data=tcont_add.SerializeToString()
            olt.zmq_client_async.async_send(data,0)
        
        except Exception as e:
            self.log.exception('Exception during add tcont', e=e)
            
    def tcont_delete_msg_send(self, olt, alloc_id):
        #tcont = self._tconts.get(tcont_id)
        try:
            msg_hdr = OltMsgCommonHdr(
                type=OLT_PON_DELETE_TCONT,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )
            data=msg_hdr.SerializeToString()
            olt.zmq_client_async.async_send(data,1)
        
            tcont_delete = OltPonDeleteTcont(
                #pon_port=tcont.pon_id,
                pon_port=self._pon_id,
                alloc_id=alloc_id
            )
            data=tcont_delete.SerializeToString()
            olt.zmq_client_async.async_send(data,0)
        
        except Exception as e:
            self.log.exception('Exception during delete tcont', e=e)


    def add_gemport(self, gemport, reflow=False):
        if reflow == False:
            self._gem_ports[gemport.gem_id] = gemport

        cvlan = gemport.cvlan
        uni_name = gemport.uni_name
        olt=self._olt
        uniLogicalPort = 0
        items = olt.adapter_agent.root_proxy.get('/logical_devices/{}/ports'.format(olt._logical_device.id))  
        logical_port_items = LogicalPorts(items=items)  
        for port in logical_port_items.items:
            if uni_name == port.ofp_port.name :
                uniLogicalPort = port.ofp_port.port_no
                #onu_device = olt.adapter_agent.get_device(port.device_id)
                #self.log.debug("gem_port--onu_device", onu_device=onu_device)
                break
                            
        self.log.debug('gem_port--gemportId', gemportId = gemport.gem_id)        
        self.log.debug('gem_port--cvlan', cvlan = cvlan)
        self.log.debug('gem_port--uni', uni_name = uni_name)
        
        self.log.debug('gem_port---uniLogicalPort', uniLogicalPort=uniLogicalPort)

        self.gemport_msg_send(OLT_PON_ADD_GEMPORT, uniLogicalPort, cvlan, gemport.gem_id)


    def remove_gemport(self, gemport_id, reflow=False):
        gemport = self._gem_ports.get(gemport_id)

        if gemport is None:
            return

        cvlan = gemport.cvlan
        uni_name = gemport.uni_name
        uniLogicalPort = 0

        olt=self._olt
        items = olt.adapter_agent.root_proxy.get('/logical_devices/{}/ports'.format(olt._logical_device.id))  
        logical_port_items = LogicalPorts(items=items) 
        for port in logical_port_items.items:
            if uni_name == port.ofp_port.name :
                uniLogicalPort = port.ofp_port.port_no
                break

        self.log.debug('gem_port--gemportId', gemportId = gemport.gem_id)        
        self.log.debug('gem_port--cvlan', cvlan = cvlan)
        self.log.debug('gem_port--uni', uni_name = uni_name)
        self.log.debug('gem_port---uniLogicalPort', uniLogicalPort=uniLogicalPort)

        self.gemport_msg_send(OLT_PON_DELETE_GEMPORT, uniLogicalPort, cvlan, gemport.gem_id)
        
        del self._gem_ports[gemport_id]

    def gemport_msg_send(self, msg_type, uni_logic_port, vlan, gemport_id):

        gemport = self._gem_ports.get(gemport_id)

        if gemport is None:
            return
            
        try:
            mgr_hdr = OltMsgCommonHdr(
                type=msg_type,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )

            data=mgr_hdr.SerializeToString()

            self._olt.zmq_client_async.async_send(data, 1)

            gemport_data = OltPonGemport(
                uni_logic_port = uni_logic_port,
                vlan = vlan,
                gemport_id = gemport_id,
                onu_id = gemport.onu_id,
                pon_port = gemport.pon_id
            )
            data=gemport_data.SerializeToString()
            self._olt.zmq_client_async.async_send(data, 0)
        except Exception as e:
            self.log.exception('Exception during gemport add processing', e=e)


        

