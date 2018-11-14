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

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet import reactor

from voltha.adapters.asfvolt16_olt.protos import bal_pb2, bal_pb2_grpc, \
    bal_model_types_pb2, bal_model_ids_pb2, \
    bal_indications_pb2, bal_indications_pb2_grpc, \
    asfvolt_pb2, asfvolt_pb2_grpc
from voltha.adapters.asfvolt16_olt.grpc_client import GrpcClient
from voltha.adapters.asfvolt16_olt.asfvolt16_ind_handler \
                                       import Asfvolt16IndHandler
from common.utils.nethelpers import get_my_primary_local_ipv4
from common.utils.asleep import asleep
import time
import os

"""
ASFVOLT Adapter port is 60001
"""
ADAPTER_PORT = 60001

GRPC_TIMEOUT = 5
GRPC_HEARTBEAT_TIMEOUT = 2

RESERVED_VLAN_ID = 4095


class Bal(object):
    def __init__(self, olt, log):
        self.log = log
        self.grpc_client = GrpcClient(self.log)
        self.stub = None
        self.ind_stub = None
        self.asfvolt_stub = None
        self.device_id = None
        self.olt = olt
        self.interval = 0.05
        self.ind_obj = Asfvolt16IndHandler(log)

    @inlineCallbacks
    def connect_olt(self, host_and_port, device_id, is_init=True):
        self.device_id = device_id
        self.grpc_client.connect(host_and_port)
        self.stub = bal_pb2_grpc.BalStub(self.grpc_client.channel)
        self.ind_stub = bal_indications_pb2_grpc.BalGetIndStub(self.grpc_client.channel)
        self.asfvolt_stub = asfvolt_pb2_grpc.AsfvoltStub(self.grpc_client.channel)
        self.olt.running = True

        # Right now Bi-Directional GRPC support is not there in grpc-c.
        # This code may be needed when bidirectional supported added
        # in GRPC-C
        if is_init is True:
            init = bal_pb2.BalInit()
            try:
                os.environ["SERVICE_HOST_IP"]
                adapter_ip = os.environ["SERVICE_HOST_IP"]
            except Exception as e:
                self.log.info('voltha-is-running-in-non-docker-container-environment')
                adapter_ip = get_my_primary_local_ipv4()

            ip_port = []
            ip_port.append(str(adapter_ip))
            ip_port.append(":")
            ip_port.append(str(ADAPTER_PORT))
            init.voltha_adapter_ip_port = "".join(ip_port)
            self.log.info('Adapter-port-IP', init.voltha_adapter_ip_port)
            self.log.info('connecting-olt', host_and_port=host_and_port,
                          init_details=init)
            yield self.stub.BalApiInit(init, timeout=GRPC_TIMEOUT)
            yield asleep(0.2)

    def activate_olt(self):
        self.log.info('activating-olt')
        self.set_access_terminal_admin_state(bal_model_types_pb2.BAL_STATE_UP)

    def deactivate_olt(self):
        self.log.info('deactivating-olt')
        self.set_access_terminal_admin_state(bal_model_types_pb2.BAL_STATE_DOWN)

    @inlineCallbacks
    def set_access_terminal_admin_state(self, admin_state):
        obj = bal_pb2.BalCfg()
        obj.device_id = self.device_id.encode('ascii', 'ignore')
        obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_ACCESS_TERMINAL
        obj.cfg.key.access_term_id = 0
        obj.cfg.data.admin_state = admin_state
        self.log.info('Admin-stage-change-Access-Terminal-Device',
                      admin_state=admin_state, device_id=self.device_id,
                      access_terminal_details=obj)
        yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)

    @inlineCallbacks
    def get_access_terminal_cfg(self):
        try:
            obj = bal_pb2.BalKey()
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_ACCESS_TERMINAL
            obj.access_term_key.access_term_id = 0
            access_term_cfg = yield self.stub.BalCfgGet(obj, timeout=GRPC_TIMEOUT)
            self.log.debug("rxed-access-term-cfg", access_term_cfg=access_term_cfg)
            returnValue(access_term_cfg)
        except Exception as e:
            self.log.info('get-access-terminal-cfg-exception', exc=str(e))
            return

    @inlineCallbacks
    def get_subscriber_terminal_cfg(self, sub_term_id, intf_id):
        try:
            obj = bal_pb2.BalKey()
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL
            obj.terminal_key.sub_term_id = sub_term_id
            obj.terminal_key.intf_id = intf_id
            sub_term_cfg = yield self.stub.BalCfgGet(obj, timeout=GRPC_TIMEOUT)
            self.log.debug("rxed-sub-term-cfg", sub_term_cfg=sub_term_cfg)
            returnValue(sub_term_cfg)
        except Exception as e:
            self.log.info('get-subscriber-terminal-cfg-exception', exc=str(e))
            return

    @inlineCallbacks
    def activate_pon_port(self, olt_no, pon_port, transceiver_type):
        try:
            obj = bal_pb2.BalCfg()
            #            Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_INTERFACE
            #            Fill Access Terminal Details
            obj.interface.key.intf_id = pon_port
            obj.interface.key.intf_type = bal_model_types_pb2.BAL_INTF_TYPE_PON
            obj.interface.data.admin_state = bal_model_types_pb2.BAL_STATE_UP
            obj.interface.data.transceiver_type = transceiver_type
            self.log.info('activating-pon-port-in-olt',
                          olt=olt_no, pon_port=pon_port,
                          pon_port_details=obj,
                          transceiver_type=transceiver_type)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.info('activating-pon-port-in-olt-exception', exc=str(e))
        return

    @inlineCallbacks
    def deactivate_pon_port(self, olt_no, pon_port, transceiver_type):
        try:
            obj = bal_pb2.BalCfg()
            #            Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_INTERFACE
            #            Fill Access Terminal Details
            obj.interface.key.intf_id = pon_port
            obj.interface.key.intf_type = bal_model_types_pb2.BAL_INTF_TYPE_PON
            obj.interface.data.admin_state = bal_model_types_pb2.BAL_STATE_DOWN
            obj.interface.data.transceiver_type = transceiver_type
            self.log.info('deactivating-pon-port-in-olt',
                          olt=olt_no, pon_port=pon_port,
                          pon_port_details=obj,
                          transceiver_type=transceiver_type)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.info('deactivating-pon-port in olt-exception', exc=str(e))
        return

    @inlineCallbacks
    def send_omci_request_message(self, proxy_address, msg):
        try:
            obj = bal_pb2.BalCfg()
            #            Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_PACKET
            #            Fill packet Details
            obj.packet.key.packet_send_dest.type = \
                bal_model_types_pb2.BAL_DEST_TYPE_ITU_OMCI_CHANNEL
            obj.packet.key.packet_send_dest.itu_omci_channel.sub_term_id = \
                proxy_address.onu_id
            obj.packet.key.packet_send_dest.itu_omci_channel.intf_id = \
                proxy_address.channel_id
            obj.packet.data.pkt = msg
            self.log.info('send_omci_request_message',
                          proxy_address=proxy_address.channel_id,
                          omci_msg_details=obj)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.info('send-proxied_message-exception', exc=str(e))
        return

    @inlineCallbacks
    def activate_onu(self, onu_info):
        try:
            obj = bal_pb2.BalCfg()
            # Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL
            # Fill Access Terminal Details
            obj.terminal.key.intf_id = onu_info['pon_id']
            obj.terminal.key.sub_term_id = onu_info['onu_id']
            obj.terminal.data.admin_state = bal_model_types_pb2.BAL_STATE_UP
            obj.terminal.data.serial_number.vendor_id = onu_info['vendor']
            obj.terminal.data.serial_number.vendor_specific = \
                onu_info['vendor_specific']
            #obj.terminal.data.registration_id = onu_info['reg_id']
            self.log.info('activating-ONU-in-olt',
                          onu_details=obj)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.info('activating-ONU-exception',
                          onu_info['onu_id'], exc=str(e))
        return

    @inlineCallbacks
    def packet_out(self, pkt, pkt_info):
        obj = bal_pb2.BalCfg()
        obj.device_id = self.device_id.encode('ascii', 'ignore')
        obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_PACKET
        if pkt_info['dest_type'] == 'onu':
            # Set the destination ONU info
            obj.packet.key.packet_send_dest.type = \
                bal_model_types_pb2.BAL_DEST_TYPE_SUB_TERM
            obj.packet.key.packet_send_dest.sub_term.sub_term_id = \
                pkt_info['onu_id']
            # TODO: Need to provide correct values for sub_term_uni and int_id
            # obj.packet.key.packet_send_dest.sub_term.sub_term_uni = egress_port
            obj.packet.key.packet_send_dest.sub_term.intf_id = pkt_info['intf_id']
            obj.packet.data.intf_type = bal_model_types_pb2.BAL_INTF_TYPE_PON
        elif pkt_info['dest_type'] == 'gem_port':
            obj.packet.key.packet_send_dest.type = \
                bal_model_types_pb2.BAL_DEST_TYPE_SVC_PORT
            obj.packet.key.packet_send_dest.svc_port.svc_port_id = \
                pkt_info['gem_port']
            obj.packet.key.packet_send_dest.svc_port.intf_id = \
                pkt_info['intf_id']
            obj.packet.data.intf_type = bal_model_types_pb2.BAL_INTF_TYPE_PON
        elif pkt_info['dest_type'] == 'nni':
            obj.packet.key.packet_send_dest.type = \
                bal_model_types_pb2.BAL_DEST_TYPE_NNI
            obj.packet.key.packet_send_dest.nni.intf_id = \
                pkt_info['intf_id']
        else:
            self.log.error('unsupported-dest-type',
                           dest_type=pkt_info['dest_type'])

        # Set the Packet-out info
        # TODO: Need to provide correct value for intf_id
        obj.packet.data.pkt = pkt
        self.log.debug('sending-packet-out',
                      packet_out_details=obj)
        yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)

    @inlineCallbacks
    def add_flow(self, onu_id=None, intf_id=None, network_int_id=None,
                 flow_id=None, gem_port=None, classifier_info=None,
                 is_downstream=None, action_info=None,
                 dba_sched_id=None, queue_id=None, queue_sched_id=None):
        try:
            obj = bal_pb2.BalCfg()
            # Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_FLOW
            # Fill Access Terminal Details
            # To-DO flow ID need to be retrieved from flow details
            obj.flow.key.flow_id = flow_id
            if is_downstream is False:
                obj.flow.key.flow_type = \
                    bal_model_types_pb2.BAL_FLOW_TYPE_UPSTREAM
                obj.flow.data.dba_tm_sched_id = dba_sched_id
            else:
                obj.flow.key.flow_type = \
                    bal_model_types_pb2.BAL_FLOW_TYPE_DOWNSTREAM

            if queue_sched_id:
                obj.flow.data.queue.sched_id = queue_sched_id
            if queue_id:
                obj.flow.data.queue.queue_id = queue_id

            obj.flow.data.admin_state = bal_model_types_pb2.BAL_STATE_UP
            if intf_id is not None:
                obj.flow.data.access_int_id = intf_id
            if network_int_id is not None:
                obj.flow.data.network_int_id = network_int_id
            if onu_id:
                obj.flow.data.sub_term_id = onu_id
            if gem_port:
                obj.flow.data.svc_port_id = gem_port
            obj.flow.data.classifier.presence_mask = 0

            if classifier_info is None:
                classifier_info = dict()

            if 'eth_type' in classifier_info:
                obj.flow.data.classifier.ether_type = \
                    classifier_info['eth_type']
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_ETHER_TYPE
            if 'ip_proto' in classifier_info:
                obj.flow.data.classifier.ip_proto = \
                    classifier_info['ip_proto']
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_IP_PROTO
            if 'vlan_vid' in classifier_info:
                obj.flow.data.classifier.o_vid = \
                    classifier_info['vlan_vid']
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_O_VID
            if 'vlan_pcp' in classifier_info:
                obj.flow.data.classifier.o_pbits = \
                    classifier_info['vlan_pcp']
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_O_PBITS
            if 'udp_src' in classifier_info:
                obj.flow.data.classifier.src_port = \
                    classifier_info['udp_src']
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_SRC_PORT
            if 'udp_dst' in classifier_info:
                obj.flow.data.classifier.dst_port = \
                    classifier_info['udp_dst']
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_DST_PORT
            if 'ipv4_dst' in classifier_info:
                obj.flow.data.classifier.dst_ip = \
                    classifier_info['ipv4_dst']
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_DST_IP
            if 'ipv4_src' in classifier_info:
                obj.flow.data.classifier.src_ip = \
                    classifier_info['ipv4_src']
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_SRC_IP
            if 'metadata' in classifier_info:
                obj.flow.data.classifier.i_vid = \
                    classifier_info['metadata']
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_I_VID
            if 'pkt_tag_type' in classifier_info:
                if classifier_info['pkt_tag_type'] == 'single_tag':
                    obj.flow.data.classifier.pkt_tag_type = \
                        bal_model_types_pb2.BAL_PKT_TAG_TYPE_SINGLE_TAG
                elif classifier_info['pkt_tag_type'] == 'double_tag':
                    obj.flow.data.classifier.pkt_tag_type = \
                        bal_model_types_pb2.BAL_PKT_TAG_TYPE_DOUBLE_TAG
                elif classifier_info['pkt_tag_type'] == 'untagged':
                    obj.flow.data.classifier.pkt_tag_type = \
                        bal_model_types_pb2.BAL_PKT_TAG_TYPE_UNTAGGED
                else:
                    obj.flow.data.classifier.pkt_tag_type = \
                        bal_model_types_pb2.BAL_PKT_TAG_TYPE_NONE
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_PKT_TAG_TYPE

            if action_info:
                obj.flow.data.action.presence_mask = 0
                obj.flow.data.action.cmds_bitmask = 0
                if 'pop_vlan' in action_info:
                    obj.flow.data.action.o_vid = action_info['vlan_vid']
                    obj.flow.data.action.cmds_bitmask |= \
                        bal_model_types_pb2.BAL_ACTION_CMD_ID_REMOVE_OUTER_TAG
                    obj.flow.data.action.presence_mask |= \
                        bal_model_types_pb2.BAL_ACTION_ID_CMDS_BITMASK
                    obj.flow.data.action.presence_mask |= \
                        bal_model_types_pb2.BAL_ACTION_ID_O_VID
                elif 'push_vlan' in action_info:
                    obj.flow.data.action.o_vid = action_info['vlan_vid']
                    obj.flow.data.action.cmds_bitmask |= \
                        bal_model_types_pb2.BAL_ACTION_CMD_ID_ADD_OUTER_TAG
                    obj.flow.data.action.presence_mask |= \
                        bal_model_types_pb2.BAL_ACTION_ID_CMDS_BITMASK
                    obj.flow.data.action.presence_mask |= \
                        bal_model_types_pb2.BAL_ACTION_ID_O_VID
                elif 'trap_to_host' in action_info:
                    obj.flow.data.action.cmds_bitmask |= \
                        bal_model_types_pb2.BAL_ACTION_CMD_ID_TRAP_TO_HOST
                    obj.flow.data.action.presence_mask |= \
                        bal_model_types_pb2.BAL_ACTION_ID_CMDS_BITMASK
                else:
                    self.log.info('Invalid-action-field',
                                 action_info=action_info)
                    return
            self.log.info('adding-flow-to-OLT-Device',
                          flow_details=obj)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.info('add_flow-exception',
                          flow_id, onu_id, exc=str(e))
        return

    @inlineCallbacks
    def deactivate_ftth_flow(self, flow_id,
                             is_downstream,
                             onu_id=None,
                             intf_id=None,
                             network_int_id=None,
                             gemport_id=None,
                             stag=None,
                             ctag=None,
                             dba_sched_id=None,
                             us_scheduler_id=None,
                             ds_scheduler_id=None,
                             queue_id=None):
        try:
            obj = bal_pb2.BalCfg()
            # Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_FLOW
            # Fill Access Terminal Details
            # To-DO flow ID need to be retrieved from flow details
            obj.flow.key.flow_id = flow_id
            obj.flow.data.admin_state = bal_model_types_pb2.BAL_STATE_DOWN
            if intf_id is not None:
                obj.flow.data.access_int_id = intf_id
            if network_int_id is not None:
                obj.flow.data.network_int_id = network_int_id
            if onu_id is not None:
                obj.flow.data.sub_term_id = onu_id
            if gemport_id is not None:
                obj.flow.data.svc_port_id = gemport_id

            if is_downstream is True:
                obj.flow.key.flow_type = \
                    bal_model_types_pb2.BAL_FLOW_TYPE_DOWNSTREAM
                if stag is not None:
                    obj.flow.data.classifier.o_vid = stag
                    obj.flow.data.classifier.presence_mask |= \
                        bal_model_types_pb2.BAL_CLASSIFIER_ID_O_VID
                    obj.flow.data.classifier.pkt_tag_type = \
                        bal_model_types_pb2.BAL_PKT_TAG_TYPE_DOUBLE_TAG
                    obj.flow.data.classifier.presence_mask |= \
                        bal_model_types_pb2.BAL_CLASSIFIER_ID_PKT_TAG_TYPE
                    obj.flow.data.action.cmds_bitmask |= \
                        bal_model_types_pb2.BAL_ACTION_CMD_ID_REMOVE_OUTER_TAG
                    obj.flow.data.action.presence_mask |= \
                        bal_model_types_pb2.BAL_ACTION_ID_CMDS_BITMASK
                    obj.flow.data.action.o_vid = stag
                    obj.flow.data.action.presence_mask |= \
                        bal_model_types_pb2.BAL_ACTION_ID_O_VID
                if ctag != RESERVED_VLAN_ID:
                    obj.flow.data.classifier.i_vid = ctag
                    obj.flow.data.classifier.presence_mask |= \
                        bal_model_types_pb2.BAL_CLASSIFIER_ID_I_VID
            else:
                obj.flow.key.flow_type = \
                    bal_model_types_pb2.BAL_FLOW_TYPE_UPSTREAM
                obj.flow.data.classifier.pkt_tag_type = \
                    bal_model_types_pb2.BAL_PKT_TAG_TYPE_SINGLE_TAG
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_PKT_TAG_TYPE
                obj.flow.data.action.cmds_bitmask |= \
                    bal_model_types_pb2.BAL_ACTION_CMD_ID_ADD_OUTER_TAG
                obj.flow.data.action.presence_mask |= \
                    bal_model_types_pb2.BAL_ACTION_ID_CMDS_BITMASK
                obj.flow.data.action.o_vid = stag
                obj.flow.data.action.presence_mask |= \
                    bal_model_types_pb2.BAL_ACTION_ID_O_VID
                if ctag != RESERVED_VLAN_ID:
                    obj.flow.data.classifier.o_vid = ctag
                    obj.flow.data.classifier.presence_mask |= \
                        bal_model_types_pb2.BAL_CLASSIFIER_ID_O_VID

            if dba_sched_id is not None:
                obj.flow.data.dba_tm_sched_id = dba_sched_id

            if queue_id is not None:
                obj.flow.data.queue.queue_id = queue_id
                if ds_scheduler_id is not None:
                    obj.flow.data.queue.sched_id = ds_scheduler_id
            else:
                obj.flow.data.queue.queue_id = 0
                if us_scheduler_id is not None:
                    obj.flow.data.queue.sched_id = us_scheduler_id

            self.log.info('deactivating-flows-from-OLT-Device',
                          flow_details=obj)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.exception('deactivate_flow-exception',
                          flow_id, onu_id, exc=str(e))
        return

    @inlineCallbacks
    def deactivate_no_l2_mod_flow(self, flow_id,
                             is_downstream,
                             onu_id=None,
                             intf_id=None,
                             network_int_id=None,
                             gemport_id=None,
                             stag=None,
                             ctag=None,
                             dba_sched_id=None,
                             us_scheduler_id=None,
                             ds_scheduler_id=None,
                             queue_id=None):
        try:
            obj = bal_pb2.BalCfg()
            # Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_FLOW
            # Fill Access Terminal Details
            # To-DO flow ID need to be retrieved from flow details
            obj.flow.key.flow_id = flow_id
            obj.flow.data.admin_state = bal_model_types_pb2.BAL_STATE_DOWN
            if intf_id is not None:
                obj.flow.data.access_int_id = intf_id
            if network_int_id is not None:
                obj.flow.data.network_int_id = network_int_id
            if onu_id is not None:
                obj.flow.data.sub_term_id = onu_id
            if gemport_id is not None:
                obj.flow.data.svc_port_id = gemport_id
            if is_downstream is True:
                obj.flow.key.flow_type = \
                    bal_model_types_pb2.BAL_FLOW_TYPE_DOWNSTREAM
            else:
                obj.flow.key.flow_type = \
                    bal_model_types_pb2.BAL_FLOW_TYPE_UPSTREAM

            obj.flow.data.classifier.pkt_tag_type = \
                bal_model_types_pb2.BAL_PKT_TAG_TYPE_DOUBLE_TAG
            obj.flow.data.classifier.presence_mask |= \
                bal_model_types_pb2.BAL_CLASSIFIER_ID_PKT_TAG_TYPE
            obj.flow.data.classifier.o_vid = stag
            if ctag != RESERVED_VLAN_ID:
                obj.flow.data.classifier.o_vid = ctag
                obj.flow.data.classifier.presence_mask |= \
                    bal_model_types_pb2.BAL_CLASSIFIER_ID_O_VID

            if dba_sched_id is not None:
                obj.flow.data.dba_tm_sched_id = dba_sched_id

            if queue_id is not None:
                obj.flow.data.queue.queue_id = queue_id
                if ds_scheduler_id is not None:
                    obj.flow.data.queue.sched_id = ds_scheduler_id
            else:
                obj.flow.data.queue.queue_id = 0
                if us_scheduler_id is not None:
                    obj.flow.data.queue.sched_id = us_scheduler_id

            self.log.info('deactivating-flows-from-OLT-Device',
                          flow_details=obj)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.exception('deactivate_flow-exception',
                          flow_id, onu_id, exc=str(e))
        return

    @inlineCallbacks
    def deactivate_eapol_flow(self, flow_id, is_downstream,
                              onu_id=None,
                              intf_id=None,
                              network_int_id=None,
                              gemport_id=None,
                              stag=None,
                              dba_sched_id=None,
                              queue_id=None,
                              queue_sched_id=None):
        try:
            obj = bal_pb2.BalCfg()
            # Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_FLOW
            # Fill Access Terminal Details
            # To-DO flow ID need to be retrieved from flow details
            obj.flow.key.flow_id = flow_id
            obj.flow.data.admin_state = bal_model_types_pb2.BAL_STATE_DOWN
            if intf_id is not None:
                obj.flow.data.access_int_id = intf_id
            if network_int_id is not None:
                obj.flow.data.network_int_id = network_int_id
            if onu_id is not None:
                obj.flow.data.sub_term_id = onu_id
            if gemport_id is not None:
                obj.flow.data.svc_port_id = gemport_id

            if is_downstream is True:
                obj.flow.key.flow_type = \
                    bal_model_types_pb2.BAL_FLOW_TYPE_DOWNSTREAM
            else:
                obj.flow.key.flow_type = \
                    bal_model_types_pb2.BAL_FLOW_TYPE_UPSTREAM

            obj.flow.data.classifier.pkt_tag_type = \
                bal_model_types_pb2.BAL_PKT_TAG_TYPE_SINGLE_TAG
            obj.flow.data.classifier.presence_mask |= \
                bal_model_types_pb2.BAL_CLASSIFIER_ID_PKT_TAG_TYPE
            obj.flow.data.classifier.o_vid = stag
            obj.flow.data.classifier.presence_mask |= \
                bal_model_types_pb2.BAL_CLASSIFIER_ID_O_VID
            obj.flow.data.action.cmds_bitmask |= \
                bal_model_types_pb2.BAL_ACTION_CMD_ID_TRAP_TO_HOST
            obj.flow.data.action.presence_mask |= \
                bal_model_types_pb2.BAL_ACTION_ID_CMDS_BITMASK
            if dba_sched_id:
                obj.flow.data.dba_tm_sched_id = dba_sched_id
            if queue_id:
                obj.flow.data.queue.queue_id = queue_id
            if queue_sched_id:
                obj.flow.data.queue.sched_id = queue_sched_id
            self.log.info('deactivating-eapol-flows-from-OLT-Device',
                          flow_details=obj)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.exception('deactivate-eapol-flow-exception',
                               flow_id, onu_id, exc=str(e))
        return

    @inlineCallbacks
    def create_scheduler(self, id, direction, owner_info, num_priority,
                         rate_info=None):
        try:
            obj = bal_pb2.BalCfg()
            # Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_TM_SCHED
            # Fill Access Terminal Details
            if direction == 'downstream':
                obj.tm_sched_cfg.key.dir = \
                    bal_model_types_pb2.BAL_TM_SCHED_DIR_DS
            else:
                obj.tm_sched_cfg.key.dir = \
                    bal_model_types_pb2.BAL_TM_SCHED_DIR_US
            obj.tm_sched_cfg.key.id = id

            if owner_info['type'] == 'agg_port':
                obj.tm_sched_cfg.data.owner.type = \
                    bal_model_types_pb2.BAL_TM_SCHED_OWNER_TYPE_AGG_PORT
                obj.tm_sched_cfg.data.owner.agg_port.presence_mask = 0
                obj.tm_sched_cfg.data.owner.agg_port.intf_id = \
                    owner_info['intf_id']
                obj.tm_sched_cfg.data.owner.agg_port.presence_mask |= \
                    bal_model_types_pb2.BAL_TM_SCHED_OWNER_AGG_PORT_ID_INTF_ID
                obj.tm_sched_cfg.data.owner.agg_port.sub_term_id = \
                    owner_info['onu_id']
                obj.tm_sched_cfg.data.owner.agg_port.presence_mask |= \
                    bal_model_types_pb2.BAL_TM_SCHED_OWNER_AGG_PORT_ID_SUB_TERM_ID
                obj.tm_sched_cfg.data.owner.agg_port.agg_port_id = \
                    owner_info['alloc_id']
                obj.tm_sched_cfg.data.owner.agg_port.presence_mask |= \
                    bal_model_types_pb2.BAL_TM_SCHED_OWNER_AGG_PORT_ID_AGG_PORT_ID
            else:
                self.log.error('Not-supported-scheduling-type',
                               sched_type=owner_info['type'])
                return
            #obj.tm_sched_cfg.data.sched_type = \
            #    bal_model_types_pb2.BAL_TM_SCHED_TYPE_SP_WFQ
            #obj.tm_sched_cfg.data.num_priorities = num_priority
            if rate_info is not None:
                obj.tm_sched_cfg.data.rate.presence_mask = \
                    bal_model_types_pb2.BAL_TM_SHAPING_ID_ALL
                obj.tm_sched_cfg.data.rate.cir = rate_info['cir']
                obj.tm_sched_cfg.data.rate.pir = rate_info['pir']
                obj.tm_sched_cfg.data.rate.burst = rate_info['burst']

            self.log.info('Creating-Scheduler',
                          scheduler_details=obj)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.info('creat-scheduler-exception',
                          olt=self.olt.olt_id,
                          sched_id=id,
                          direction=direction,
                          owner=owner_info,
                          rate=rate_info,
                          exc=str(e))
        return

    @inlineCallbacks
    def deactivate_onu(self, onu_info):
        try:
            obj = bal_pb2.BalCfg()
            # Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL
            # Fill Access Terminal Details
            obj.terminal.key.intf_id = onu_info['pon_id']
            obj.terminal.key.sub_term_id = onu_info['onu_id']
            obj.terminal.data.admin_state = bal_model_types_pb2.BAL_STATE_DOWN
            obj.terminal.data.serial_number.vendor_id = onu_info['vendor']
            obj.terminal.data.serial_number.vendor_specific = \
                onu_info['vendor_specific']
            obj.terminal.data.registration_id = onu_info['reg_id']
            self.log.info('deactivating-ONU-in-olt',
                          onu_details=obj)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.info('deactivating-ONU-exception',
                          onu_info['onu_id'], exc=str(e))
        return

    @inlineCallbacks
    def delete_onu(self, onu_info):
        try:
            obj = bal_pb2.BalKey()
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_SUBSCRIBER_TERMINAL
            # Fill Access Terminal Details
            obj.terminal_key.sub_term_id = onu_info['onu_id']
            obj.terminal_key.intf_id = onu_info['pon_id']
            self.log.info('delete-ONU-in-olt',
                          onu_details=obj)
            yield self.stub.BalCfgClear(obj, timeout=5)
        except Exception as e:
            self.log.info('delete-ONU-exception',
                          onu_info['onu_id'], exc=str(e))
        return

    @inlineCallbacks
    def delete_scheduler(self, id, direction):
        try:
            obj = bal_pb2.BalKey()
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_TM_SCHED
            # Fill Access Terminal Details
            if direction == 'downstream':
                obj.tm_sched_key.dir =\
                    bal_model_types_pb2.BAL_TM_SCHED_DIR_DS
            else:
                obj.tm_sched_key.dir = \
                    bal_model_types_pb2.BAL_TM_SCHED_DIR_US
            obj.tm_sched_key.id = id
            self.log.info('Deleting Scheduler',
                          scheduler_details=obj)
            yield self.stub.BalCfgClear(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.info('creat-scheduler-exception',
                          olt=self.olt.olt_id,
                          sched_id=id,
                          direction=direction,
                          exc=str(e))
        return

    @inlineCallbacks
    def delete_flow(self, flow_id, is_downstream):
        try:
            obj = bal_pb2.BalKey()
            # Fill Header details
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_FLOW
            obj.flow_key.flow_id = flow_id
            if is_downstream is False:
                obj.flow_key.flow_type = \
                    bal_model_types_pb2.BAL_FLOW_TYPE_UPSTREAM
            else:
                obj.flow_key.flow_type = \
                    bal_model_types_pb2.BAL_FLOW_TYPE_DOWNSTREAM

            self.log.info('deleting-flows-from-OLT-Device',
                          flow_details=obj)
            resp = yield self.stub.BalCfgClear(obj, timeout=5)
        except Exception as e:
            self.log.exception('delete_flow-exception',
                          flow_id, e=e)
        return

    @inlineCallbacks
    def get_bal_interface_stats(self, intf_id, interface_type):
        # This happens too often and the below log is unnecessary.
        # The status are anyway available on kafka
        # self.log.debug('Fetching-Statistics')
        try:
            obj = bal_model_types_pb2.BalInterfaceKey()
            obj.intf_id = intf_id
            obj.intf_type = interface_type
            stats = yield self.stub.BalCfgStatGet(obj, timeout=GRPC_TIMEOUT)
            # This happens too often and the below log is unnecessary.
            # The status are anyway available on kafka
            # self.log.debug('Fetching-statistics-success',
            #               stats_data=stats.data)
            returnValue(stats)
        except Exception as e:
            self.log.info('Fetching-statistics-failed', exc=str(e))

    @inlineCallbacks
    def set_bal_reboot(self, device_id):
        self.log.info('Set-Reboot')
        try:
            obj = bal_pb2.BalReboot()
            obj.device_id = device_id
            err = yield self.stub.BalApiReboot(obj, timeout=GRPC_TIMEOUT)
            self.log.info('OLT-Reboot-Success', reboot_err=err)
            returnValue(err)
        except Exception as e:
            self.log.info('OLT-Reboot-failed', exc=str(e))

    @inlineCallbacks
    def get_bal_heartbeat(self, device_id):
        self.log.info('Get-HeartBeat')
        try:
            obj = bal_pb2.BalHeartbeat()
            obj.device_id = device_id
            rebootStatus = yield self.stub.BalApiHeartbeat(
                                 obj, timeout=GRPC_HEARTBEAT_TIMEOUT)
            self.log.info('OLT-HeartBeat-Response-Received-from',
                          device=device_id, rebootStatus=rebootStatus)
            returnValue(rebootStatus)
        except Exception as e:
            self.log.info('OLT-HeartBeat-failed', exc=str(e))

    @inlineCallbacks
    def get_asfvolt_system_info(self, device_id):
        self.log.info('get-asfvolt-system-info')
        try:
            obj = bal_pb2.BalDefault()
            obj.device_id = device_id
            asfvolt_system_info = \
                 yield self.asfvolt_stub.AsfvoltGetSystemInfo(obj, timeout=GRPC_TIMEOUT)
            self.log.debug('asf-volt-system-info',
                            asfvolt_system_info=asfvolt_system_info)
            returnValue(asfvolt_system_info)
        except Exception as e:
            self.log.error('get-asfvolt-system-info-failed', exc=str(e))
            returnValue(None)

    @inlineCallbacks
    def get_asfvolt_sfp_presence_map(self, device_id):
        self.log.info('get-asfvolt-sfp-presence-map')
        sfp_presence_bitmap = None
        try:
            obj = bal_pb2.BalDefault()
            obj.device_id = device_id
            sfp_presence_bitmap = \
                 yield self.asfvolt_stub.AsfvoltGetSfpPresenceBitmap(obj, timeout=GRPC_TIMEOUT)
            self.log.debug('asf-volt-sfp-presence-bit-map',
                           sfp_presence_bitmap=sfp_presence_bitmap.bitmap)
            returnValue(sfp_presence_bitmap.bitmap)
        except Exception as e:
            self.log.error('get-asfvolt-sfp-presence-map-failed', exc=str(e))
            returnValue(sfp_presence_bitmap)

    def get_indication_info(self, device_id):
        while self.olt.running:
            try:
                obj = bal_pb2.BalDefault()
                obj.device_id = str(device_id)
                bal_ind = self.ind_stub.BalGetIndFromDevice(obj, timeout=GRPC_TIMEOUT)
                if bal_ind.ind_present == True:
                    self.ind_obj.handle_indication_from_bal(bal_ind, self.olt)
            except Exception as e:
                self.log.info('Failed-to-get-indication-info', exc=str(e))

            time.sleep(self.interval)

        self.log.debug('stop-indication-receive-thread')

    @inlineCallbacks
    def create_queue(self, id, direction, sched_id,
                     priority=None, weight=None, rate_info=None):
        try:
            obj = bal_pb2.BalCfg()
            # Fill Header details
            obj.device_id = self.device_id.encode('ascii', 'ignore')
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_TM_QUEUE
            # Fill Queue Cfg Details
            if direction == 'downstream':
                obj.tm_queue_cfg.key.sched_dir = \
                    bal_model_types_pb2.BAL_TM_SCHED_DIR_DS
            else:
                obj.tm_queue_cfg.key.sched_dir = \
                    bal_model_types_pb2.BAL_TM_SCHED_DIR_US
            obj.tm_queue_cfg.key.id = id
            obj.tm_queue_cfg.key.sched_id = sched_id
            '''
            TO-DO:By default the schedular created is of type sp_wfq,
            which requires either priority or weight but not both.
            Need to fetch schd_type then assign either one of them
            '''
            if weight is not None:
                obj.tm_queue_cfg.data.weight = weight

            if rate_info is not None:
                obj.tm_queue_cfg.data.rate.presence_mask = \
                    bal_model_types_pb2.BAL_TM_SHAPING_ID_ALL
                obj.tm_queue_cfg.data.rate.cir = rate_info['cir']
                obj.tm_queue_cfg.data.rate.pir = rate_info['pir']
                obj.tm_queue_cfg.data.rate.burst = rate_info['burst']
            else:
                obj.tm_queue_cfg.data.rate.presence_mask = \
                    bal_model_types_pb2.BAL_TM_SHAPING_ID_NONE
            obj.tm_queue_cfg.data.creation_mode = \
                    bal_model_types_pb2.BAL_TM_CREATION_MODE_MANUAL
            obj.tm_queue_cfg.data.ref_count = 0

            self.log.info('Creating-Queue',
                          scheduler_details=obj)
            yield self.stub.BalCfgSet(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.info('create-queue-exception',
                          olt=self.olt.olt_id,
                          queue_id=id,
                          direction=direction,
                          sched_id=sched_id,
                          priority=priority,
                          weight=weight,
                          rate_info=rate_info,
                          exc=str(e))
        return

    @inlineCallbacks
    def delete_queue(self, id, direction, sched_id):
        try:
            obj = bal_pb2.BalKey()
            obj.hdr.obj_type = bal_model_ids_pb2.BAL_OBJ_ID_TM_QUEUE
            # Fill Queue Key Details
            if direction == 'downstream':
                obj.tm_queue_key.sched_dir =\
                    bal_model_types_pb2.BAL_TM_SCHED_DIR_DS
            else:
                obj.tm_queue_key.sched_dir = \
                    bal_model_types_pb2.BAL_TM_SCHED_DIR_US
            obj.tm_queue_key.id = id
            obj.tm_queue_key.sched_id = sched_id
            self.log.info('Deleting-Queue',
                          queue_details=obj)
            yield self.stub.BalCfgClear(obj, timeout=GRPC_TIMEOUT)
        except Exception as e:
            self.log.info('delete-queue-exception',
                          olt=self.olt.olt_id,
                          queue_id=id,
                          direction=direction,
                          sched_id=sched_id,
                          exc=str(e))
        return
