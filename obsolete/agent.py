# Copyright 2017-present Open Networking Foundation
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
import logging
import loxi.of13 as ofp
import socket
import sys
import time

from loxi.connection import Connection
from ofagent.utils import pp


class Agent(object):

    def __init__(self, controller, datapath_id,
                 store, backend, retry_interval=1):
        self.ip = controller.split(':')[0]
        self.port = int(controller.split(':')[1])
        self.datapath_id = datapath_id
        self.store = store
        self.backend = backend
        self.exiting = False
        self.retry_interval = retry_interval
        self.cxn = None
        self.soc = None

    def run(self):
        self.connect()

    def connect(self):
        """
        Connect to a controller
        """
        while not self.exiting:
            self.cxn = None
            self.soc = soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                soc.connect((self.ip, self.port))
            except socket.error, e:
                logging.info(
                    "Cannot connect to controller (errno=%d), "
                    "retrying in %s secs" %
                    (e.errno, self.retry_interval))
            else:
                logging.info("Connected to controller")
                soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
                self.cxn = cxn = Connection(self.soc)
                cxn.daemon = False
                cxn.start()
                try:
                    self.handle_protocol()
                except Exception, e:
                    logging.info(
                        "Connection was lost (%s), will retry in %s secs" %
                        (e, self.retry_interval))
            time.sleep(self.retry_interval)

    def stop(self):
        if self.cxn is not None:
            self.cxn.stop()
        if self.soc is not None:
            self.soc.close()

    def signal_flow_mod_error(self, code, data):
        msg = ofp.message.flow_mod_failed_error_msg(code=code, data=data)
        self.cxn.send(msg)

    def signal_group_mod_error(self, code, data):
        msg = ofp.message.group_mod_failed_error_msg(code=code, data=data)
        self.cxn.send(msg)

    def signal_flow_removal(self, flow):
        assert isinstance(flow, ofp.common.flow_stats_entry)
        msg = ofp.message.flow_removed(
            cookie=flow.cookie,
            priority=flow.priority,
            reason=None, # TODO
            table_id=flow.table_id,
            duration_sec=flow.duration_sec,
            duration_nsec=flow.duration_nsec,
            idle_timeout=flow.idle_timeout,
            hard_timeout=flow.hard_timeout,
            packet_count=flow.packet_count,
            byte_count=flow.byte_count,
            match=flow.match)
        self.cxn.send(msg)

    def send_packet_in(self, data, in_port):
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        msg = ofp.message.packet_in(
            reason=ofp.OFPR_ACTION,
            match=match,
            data=data)
        self.cxn.send(msg)

    def handle_protocol(self):

        cxn = self.cxn

        # Send initial hello
        cxn.send(ofp.message.hello())

        if not cxn.recv(lambda msg: msg.type == ofp.OFPT_HELLO):
            raise Exception("Did not receive initial HELLO")

        while True:

            try:
                req = cxn.recv(lambda msg: True)
            except AssertionError, e:
                raise Exception("Connection is no longer alive")

            print(pp(req))

            if req is None:
                # this simply means we timed out
                # later we can use this to do other stuff
                # for now we simply ignore this and loop back
                pass

            elif req.type == ofp.OFPT_FEATURES_REQUEST:
                msg = ofp.message.features_reply(
                    xid=req.xid,
                    datapath_id=self.datapath_id,
                    n_buffers=256,
                    n_tables=2,
                    capabilities= (
                          ofp.OFPC_FLOW_STATS
                        | ofp.OFPC_TABLE_STATS
                        | ofp.OFPC_PORT_STATS
                        | ofp.OFPC_GROUP_STATS
                    )
                )
                cxn.send(msg)

            elif req.type == ofp.OFPT_STATS_REQUEST:

                if req.stats_type == ofp.OFPST_PORT_DESC:
                    # port stats request
                    msg = ofp.message.port_desc_stats_reply(
                        xid=req.xid,
                        #flags=None,
                        entries=self.store.port_list())
                    cxn.send(msg)

                elif req.stats_type == ofp.OFPST_DESC:
                    # device description
                    msg = ofp.message.desc_stats_reply(
                        xid=req.xid,
                        flags=None,
                        mfr_desc=self.backend.mfr_desc,
                        hw_desc=self.backend.hw_desc,
                        sw_desc="pyofagent",
                        serial_num=self.backend.get_serial_num(),
                        dp_desc=self.backend.get_dp_desc())
                    cxn.send(msg)

                elif req.stats_type == ofp.OFPST_FLOW:
                    # flow stats requested
                    msg = ofp.message.flow_stats_reply(
                        xid=req.xid, entries=self.store.flow_list())
                    cxn.send(msg)

                elif req.stats_type == ofp.OFPST_TABLE:
                    # table stats requested
                    msg = ofp.message.table_stats_reply(
                        xid=req.xid, entries=self.store.table_stats())
                    cxn.send(msg)

                elif req.stats_type == ofp.OFPST_PORT:
                    # port list
                    msg = ofp.message.port_stats_reply(
                        xid=req.xid, entries=self.store.port_stats())
                    cxn.send(msg)

                elif req.stats_type == ofp.OFPST_GROUP:
                    msg = ofp.message.group_stats_reply(
                        xid=req.xid, entries=self.store.group_stats())
                    cxn.send(msg)

                elif req.stats_type == ofp.OFPST_GROUP_DESC:
                    msg = ofp.message.group_desc_stats_reply(
                        xid=req.xid, entries=self.store.group_list())
                    cxn.send(msg)

                elif req.stats_type == ofp.OFPST_METER:
                    msg = ofp.message.meter_stats_reply(
                        xid=req.xid, entries=[])
                    cxn.send(msg)

                else:
                    logging.error("Unhandled stats type: %d in request:"
                                  % req.stats_type)
                    logging.error(pp(req))

            elif req.type == ofp.OFPT_SET_CONFIG:
                # TODO ignored for now
                pass

            elif req.type == ofp.OFPT_BARRIER_REQUEST:
                # TODO this will be the place to commit all changes before
                # replying
                # but now we send a reply right away
                msg = ofp.message.barrier_reply(xid=req.xid)
                cxn.send(msg)

            elif req.type == ofp.OFPT_GET_CONFIG_REQUEST:
                # send back configuration reply
                msg = ofp.message.get_config_reply(
                    xid=req.xid, miss_send_len=ofp.OFPCML_NO_BUFFER)
                cxn.send(msg)

            elif req.type == ofp.OFPT_ROLE_REQUEST:
                # TODO this is where we shall manage which connection is active
                # now we simply verify that the role request is for active and
                # reply
                if req.role != ofp.OFPCR_ROLE_MASTER:
                    self.stop()
                    sys.exit(1)
                msg = ofp.message.role_reply(
                    xid=req.xid, role=req.role,
                    generation_id=req.generation_id)
                cxn.send(msg)

            elif req.type == ofp.OFPT_PACKET_OUT:
                in_port = req.in_port
                data = req.data
                for action in req.actions:
                    if action.type == ofp.OFPAT_OUTPUT:
                        port = action.port
                        self.backend.packet_out(in_port, port, data)
                    else:
                        logging.warn("Unhandled packet out action type %s"
                                     % action.type)

            elif req.type == ofp.OFPT_FLOW_MOD:

                command = req._command

                if command == ofp.OFPFC_ADD:
                    self.store.flow_add(req)

                elif command == ofp.OFPFC_DELETE:
                    self.store.flow_delete(req)

                elif command == ofp.OFPFC_DELETE_STRICT:
                    self.store.flow_delete_strict(req)

                elif command == ofp.OFPFC_MODIFY:
                    self.store.flow_modify(req)

                elif command == ofp.OFPFC_MODIFY_STRICT:
                    self.store.flow_modify_strict(req)

                else:
                    logging.warn("Unhandled flow mod command %s in message:"
                                 % command)
                    logging.warn(pp(req))

            elif req.type == ofp.OFPT_GROUP_MOD:

                command = req.command

                if command == ofp.OFPGC_DELETE:
                    self.store.group_delete(req)

                elif command == ofp.OFPGC_ADD:
                    self.store.group_add(req)

                elif command == ofp.OFPGC_MODIFY:
                    self.store.group_modify(req)

                else:
                    logging.warn("Unhandled group command %s in message:"
                                 % command)
                    logging.warn(pp(req))

            else:
                logging.warn("Unhandled message from controller:")
                logging.warn(pp(req))

