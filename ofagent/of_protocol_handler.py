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
from twisted.internet.defer import inlineCallbacks, returnValue

import loxi.of13 as ofp
from converter import to_loxi, pb2dict, to_grpc

log = structlog.get_logger()


class OpenFlowProtocolError(Exception): pass


class OpenFlowProtocolHandler(object):

    ofp_version = [4]  # OFAgent supported versions

    MAX_METER_IDS = 4294967295
    MAX_METER_BANDS = 255
    MAX_METER_COLORS = 255

    def __init__(self, datapath_id, device_id, agent, cxn, rpc):
        """
        The upper half of the OpenFlow protocol, focusing on message
        exchanges.
        :param agent: Reference to the Agent() instance, can be used to
          indicate critical errors to break the connection.
        :param cxn: The lower level message serdes part of the OF protocol.
        :param rpc: The application level stub on which RPC calls
          are made as result of processing incoming OpenFlow request messages.
        """
        self.datapath_id = datapath_id
        self.device_id = device_id
        self.agent = agent
        self.cxn = cxn
        self.rpc = rpc
        self.role = None

        self.count_pkt_in = 0
        self.count_pkt_out = 0

    @inlineCallbacks
    def start(self):
        """A new call is made after a fresh reconnect"""

        log.debug('starting')

        try:
            support = False
            # send initial hello message
            self.cxn.send(ofp.message.hello(elements=[ofp.common.hello_elem_versionbitmap(
                bitmaps = [ofp.common.hello_elem_bitmap(self.ofp_version)])]))
            # expect to receive a hello message
            msg = yield self.cxn.recv_class(ofp.message.hello)
            # supports only ofp_versions till 31 and single bitmap.
            if msg:
                support = ofp.util.verify_version_support(msg,self.ofp_version)
                if not support:
                    self.cxn.send(ofp.message.hello_failed_error_msg(
                        xid=msg.xid, code=ofp.OFPHFC_INCOMPATIBLE,
                        data='i support only 1.3'))
                    log.error('peer-do-not-support-OpenFlow-version',self.ofp_version)

            while support:
                req = yield self.cxn.recv_any()
                handler = self.main_handlers.get(req.type, None)
                if handler:
                    handler(self, req)
                else:
                    log.error('cannot-handle',
                              request=req, xid=req.xid, type=req.type)

        except Exception, e:
            log.exception('exception', e=e)

        log.info('started')
        returnValue(self)

    def stop(self):
        log.debug('stopping')
        pass  # nothing to do yet
        log.info('stopped')

    def handle_echo_request(self, req):
        self.cxn.send(ofp.message.echo_reply(xid=req.xid))

    @inlineCallbacks
    def handle_feature_request(self, req):
        device_info = yield self.rpc.get_device_info(self.device_id)
        kw = pb2dict(device_info.switch_features)
        self.cxn.send(ofp.message.features_reply(
            xid=req.xid,
            datapath_id=self.datapath_id,
            **kw))

    def handle_stats_request(self, req):
        handler = self.stats_handlers.get(req.stats_type, None)
        if handler:
            handler(self, req)
        else:
            raise OpenFlowProtocolError(
                'Cannot handle stats request type "{}"'.format(req.stats_type))

    def handle_barrier_request(self, req):
        # not really doing barrier yet, but we respond
        # see https://jira.opencord.org/browse/CORD-823
        self.cxn.send(ofp.message.barrier_reply(xid=req.xid))

    def handle_experimenter_request(self, req):
        raise NotImplementedError()

    def handle_flow_mod_request(self, req):
        if self.role == ofp.OFPCR_ROLE_MASTER or self.role == ofp.OFPCR_ROLE_EQUAL:
           try:
              grpc_req = to_grpc(req)
           except Exception, e:
              log.exception('failed-to-convert', e=e)
           else:
              return self.rpc.update_flow_table(self.device_id, grpc_req)

        elif self.role == ofp.OFPCR_ROLE_SLAVE:
           self.cxn.send(ofp.message.bad_request_error_msg(code=ofp.OFPBRC_IS_SLAVE))

    def handle_meter_mod_request(self, req):
        if self.role == ofp.OFPCR_ROLE_MASTER or self.role == ofp.OFPCR_ROLE_EQUAL:
            try:
                grpc_req = to_grpc(req)
            except Exception, e:
                log.exception('failed-to-convert-meter-mod-request', e=e)
            else:
                return self.rpc.update_meter_mod_table(self.device_id, grpc_req)

        elif self.role == ofp.OFPCR_ROLE_SLAVE:
            self.cxn.send(ofp.message.bad_request_error_msg(code=ofp.OFPBRC_IS_SLAVE))

    @inlineCallbacks
    def handle_meter_stats_request(self, req):
        try:
            meters = yield self.rpc.list_meters(self.device_id)
            self.cxn.send(ofp.message.meter_stats_reply(
                xid=req.xid, entries=[to_loxi(m.stats) for m in meters]))
        except Exception, e:
            log.exception("failed-meter-stats-request", req=req, e=e)

    def handle_get_async_request(self, req):
        raise NotImplementedError()

    def handle_get_config_request(self, req):
        self.cxn.send(ofp.message.get_config_reply(
            xid=req.xid,
            miss_send_len=ofp.OFPCML_NO_BUFFER
        ))

    @inlineCallbacks
    def handle_group_mod_request(self, req):
        if self.role == ofp.OFPCR_ROLE_MASTER or self.role == ofp.OFPCR_ROLE_EQUAL:
           yield self.rpc.update_group_table(self.device_id, to_grpc(req))
        elif self.role == ofp.OFPCR_ROLE_SLAVE:
           self.cxn.send(ofp.message.bad_request_error_msg(code=ofp.OFPBRC_IS_SLAVE))

    def handle_role_request(self, req):
        if req.role == ofp.OFPCR_ROLE_MASTER or req.role == ofp.OFPCR_ROLE_SLAVE:
            if self.agent.generation_is_defined and (
                    ((req.generation_id - self.agent.cached_generation_id) & 0xffffffffffffffff) if abs(
                    req.generation_id - self.agent.cached_generation_id) > 0x7fffffffffffffff else (
                    req.generation_id - self.agent.cached_generation_id)) < 0:
                self.cxn.send(ofp.message.bad_request_error_msg(code=ofp.OFPRRFC_STALE))
            else:
                self.agent.generation_is_defined = True
                self.agent.cached_generation_id = req.generation_id
                self.role = req.role
                self.cxn.send(ofp.message.role_reply(
                 xid=req.xid, role=req.role, generation_id=req.generation_id))
        elif req.role == ofp.OFPCR_ROLE_EQUAL:
            self.role = req.role
            self.cxn.send(ofp.message.role_reply(
             xid=req.xid, role=req.role))

    def handle_packet_out_request(self, req):
        if self.role == ofp.OFPCR_ROLE_MASTER or self.role == ofp.OFPCR_ROLE_EQUAL:
           self.rpc.send_packet_out(self.device_id, to_grpc(req))
           self.count_pkt_out += 1
           log.debug('counters of_protocol_handler OUT - {}'.format(self.count_pkt_out))

        elif self.role == ofp.OFPCR_ROLE_SLAVE:
           self.cxn.send(ofp.message.bad_request_error_msg(code=ofp.OFPBRC_IS_SLAVE))

    def handle_set_config_request(self, req):
        # Handle set config appropriately
        # https://jira.opencord.org/browse/CORD-826
        pass

    @inlineCallbacks
    def handle_port_mod_request(self, req):
        if self.role == ofp.OFPCR_ROLE_MASTER or self.role == ofp.OFPCR_ROLE_EQUAL:
            port = yield self.rpc.get_port(self.device_id, str(req.port_no))

            if port.ofp_port.config & ofp.OFPPC_PORT_DOWN != \
                    req.config & ofp.OFPPC_PORT_DOWN:
                if req.config & ofp.OFPPC_PORT_DOWN:
                    self.rpc.disable_port(self.device_id, port.id)
                else:
                    self.rpc.enable_port(self.device_id, port.id)

        elif self.role == ofp.OFPCR_ROLE_SLAVE:
            self.cxn.send(ofp.message.bad_request_error_msg(code=ofp.OFPBRC_IS_SLAVE))

    def handle_table_mod_request(self, req):
        raise NotImplementedError()

    def handle_queue_get_config_request(self, req):
        raise NotImplementedError()

    def handle_set_async_request(self, req):
        raise NotImplementedError()

    def handle_aggregate_request(self, req):
        raise NotImplementedError

    @inlineCallbacks
    def handle_device_description_request(self, req):
        device_info = yield self.rpc.get_device_info(self.device_id)
        kw = pb2dict(device_info.desc)
        self.cxn.send(ofp.message.desc_stats_reply(xid=req.xid, **kw))

    def handle_experimenter_stats_request(self, req):
        raise NotImplementedError()

    @inlineCallbacks
    def handle_flow_stats_request(self, req):
        try:
            flow_stats = yield self.rpc.list_flows(self.device_id)
            self.cxn.send(ofp.message.flow_stats_reply(
                xid=req.xid, entries=[to_loxi(f) for f in flow_stats]))
        except Exception, e:
            log.exception('failed-flow-stats-request', req=req)

    @inlineCallbacks
    def handle_group_stats_request(self, req):
        group_stats = yield self.rpc.list_groups(self.device_id)
        self.cxn.send(ofp.message.group_stats_reply(
            xid=req.xid, entries=[to_loxi(g.stats) for g  in group_stats]))

    @inlineCallbacks
    def handle_group_descriptor_request(self, req):
        group_stats = yield self.rpc.list_groups(self.device_id)
        self.cxn.send(ofp.message.group_desc_stats_reply(
            xid=req.xid, entries=[to_loxi(g.desc) for g  in group_stats]))

    def handle_group_features_request(self, req):
        raise NotImplementedError()

    def handle_meter_config_request(self, req):
        raise NotImplementedError()

    def handle_meter_features_request(self, req):
        feature = ofp.meter_features(max_meter=OpenFlowProtocolHandler.MAX_METER_IDS,
                                     band_types=ofp.OFPMBT_DROP,
                                     capabilities=ofp.OFPMF_KBPS,
                                     max_bands=OpenFlowProtocolHandler.MAX_METER_BANDS,
                                     max_color=OpenFlowProtocolHandler.MAX_METER_COLORS)
        self.cxn.send(ofp.message.meter_features_stats_reply(xid=req.xid, flags=None,
                                                             features=feature))

    @inlineCallbacks
    def handle_port_stats_request(self, req):
        try:
            ports = yield self.rpc.list_ports(self.device_id)
            port_stats = [to_loxi(p.ofp_port_stats) for p in ports]
            of_message = ofp.message.port_stats_reply(
                xid=req.xid,entries=port_stats)
            self.cxn.send(of_message)
        except:
            log.exception('failed-port_stats-request', req=req)

    @inlineCallbacks
    def handle_port_desc_request(self, req):
        port_list = yield self.rpc.get_port_list(self.device_id)
        self.cxn.send(ofp.message.port_desc_stats_reply(
            xid=req.xid,
            #flags=None,
            entries=[to_loxi(port.ofp_port) for port in port_list]
        ))

    def handle_queue_stats_request(self, req):
        raise NotImplementedError()

    def handle_table_stats_request(self, req):
        table_stats = []  # see https://jira.opencord.org/browse/CORD-825
        self.cxn.send(ofp.message.table_stats_reply(
            xid=req.xid, entries=table_stats))

    def handle_table_features_request(self, req):
        raise NotImplementedError()

    stats_handlers = {
        ofp.OFPST_AGGREGATE: handle_aggregate_request,
        ofp.OFPST_DESC: handle_device_description_request,
        ofp.OFPST_EXPERIMENTER: handle_experimenter_stats_request,
        ofp.OFPST_FLOW: handle_flow_stats_request,
        ofp.OFPST_GROUP: handle_group_stats_request,
        ofp.OFPST_GROUP_DESC: handle_group_descriptor_request,
        ofp.OFPST_GROUP_FEATURES: handle_group_features_request,
        ofp.OFPST_METER: handle_meter_stats_request,
        ofp.OFPST_METER_CONFIG: handle_meter_config_request,
        ofp.OFPST_METER_FEATURES: handle_meter_features_request,
        ofp.OFPST_PORT: handle_port_stats_request,
        ofp.OFPST_PORT_DESC: handle_port_desc_request,
        ofp.OFPST_QUEUE: handle_queue_stats_request,
        ofp.OFPST_TABLE: handle_table_stats_request,
        ofp.OFPST_TABLE_FEATURES: handle_table_features_request
    }

    main_handlers = {
        ofp.OFPT_BARRIER_REQUEST: handle_barrier_request,
        ofp.OFPT_ECHO_REQUEST: handle_echo_request,
        ofp.OFPT_FEATURES_REQUEST: handle_feature_request,
        ofp.OFPT_EXPERIMENTER: handle_experimenter_request,
        ofp.OFPT_FLOW_MOD: handle_flow_mod_request,
        ofp.OFPT_GET_ASYNC_REQUEST: handle_get_async_request,
        ofp.OFPT_GET_CONFIG_REQUEST: handle_get_config_request,
        ofp.OFPT_GROUP_MOD: handle_group_mod_request,
        ofp.OFPT_METER_MOD: handle_meter_mod_request,
        ofp.OFPT_PACKET_OUT: handle_packet_out_request,
        ofp.OFPT_PORT_MOD: handle_port_mod_request,
        ofp.OFPT_QUEUE_GET_CONFIG_REQUEST: handle_queue_get_config_request,
        ofp.OFPT_ROLE_REQUEST: handle_role_request,
        ofp.OFPT_SET_ASYNC: handle_set_async_request,
        ofp.OFPT_SET_CONFIG: handle_set_config_request,
        ofp.OFPT_STATS_REQUEST: handle_stats_request,
        ofp.OFPT_TABLE_MOD: handle_table_mod_request,
    }

    def forward_packet_in(self, ofp_packet_in):
        if self.role == ofp.OFPCR_ROLE_MASTER or self.role == ofp.OFPCR_ROLE_EQUAL:
           log.info('sending-packet-in', ofp_packet_in=ofp_packet_in)
           self.cxn.send(to_loxi(ofp_packet_in))
           self.count_pkt_in += 1
           log.debug('counters of_protocol_handler IN - {}'.format(self.count_pkt_in))

    def forward_port_status(self, ofp_port_status):
        self.cxn.send(to_loxi(ofp_port_status))

    def forward_flow_removed(self, ofp_flow_removed):
        self.cxn.send(to_loxi(ofp_flow_removed))
