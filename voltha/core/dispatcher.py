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

"""
Dispatcher is responsible to dispatch incoming "global" gRPC requests
to the respective Voltha instance (leader, peer instance, local). Local
calls are forwarded to the LocalHandler.
"""
import structlog
from twisted.internet.defer import inlineCallbacks, returnValue
from voltha.protos.voltha_pb2_grpc import VolthaLocalServiceStub
from voltha.registry import registry
from twisted.internet import reactor
import grpc
from grpc import StatusCode
from grpc._channel import _Rendezvous
from common.utils.id_generation import get_core_id_from_device_id, \
    is_broadcast_core_id

log = structlog.get_logger()


class DispatchError(object):
    def __init__(self, error_code):
        self.error_code = error_code


class Dispatcher(object):
    def __init__(self, core, instance_id, core_store_id, grpc_port):
        self.core = core
        self.instance_id = instance_id
        self.core_store_id = core_store_id
        self.grpc_port = grpc_port
        self.local_handler = None
        self.peers_map = dict()
        self.grpc_conn_map = {}

    def start(self):
        log.debug('starting')
        self.local_handler = self.core.get_local_handler()
        reactor.callLater(0, self._start_tracking_peers)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        log.info('stopped')

    @inlineCallbacks
    def dispatch(self,
                 method_name,
                 request,
                 context,
                 core_id=None,
                 id=None,
                 broadcast=False):
        """
        Called whenever a global request is received from the NBI.  The
        request will be dispatch as follows:
        1) to a specific voltha Instance if the core_id is specified
        2) to the local Voltha Instance if the request specifies an ID that
        matches the core id of the local Voltha instance
        3) to a remote Voltha Instance if the request specifies an ID that
        matches the core id of that voltha instance
        4) to all Voltha Instances if it's a broadcast request,
        e.g. getDevices, i.e. broadcast=True.  The id may or may not be
        None. In this case, the results will be returned as a list of
        responses back to the global handler
        5) to the local voltha instance if id=None and broadcast=False.
        This occurs in cases where any Voltha instance will return the same
        output, e.g. getAdapters()
        :param method_name: rpc name
        :param id: the id in the request, if present.
        :param request: the input parameters
        :param context: grpc context
        :return: the response of that dispatching request
        """
        log.debug('start',
                  _method_name=method_name,
                  id=id,
                  request=request)

        core_id_from_request_id = None
        if id:
            try:
                core_id_from_request_id = get_core_id_from_device_id(id)
            except Exception, e:
                log.warning('invalid-id', request=request, id=id)
                returnValue(DispatchError(StatusCode.NOT_FOUND))

        try:
            # Broadcast request if set
            if broadcast:
                # broadcast to all instances (including locally)
                res = yield self._broadcast_request(method_name,
                                                    request,
                                                    context)
                returnValue(res)

            # Local Dispatch
            elif (core_id and core_id == self.core_store_id) or (not id) or \
                    (core_id_from_request_id and (
                        (core_id_from_request_id == self.core_store_id) or
                        (is_broadcast_core_id(id))
                        )
                     ):
                returnValue(self._local_dispatch(self.core_store_id,
                                                 method_name,
                                                 request,
                                                 context))
            # Peer Dispatch
            elif core_id_from_request_id:
                res = yield self._dispatch_to_peer(core_id_from_request_id,
                                                   method_name,
                                                   request,
                                                   context)
                returnValue(res)
            else:
                log.warning('invalid-request', request=request, id=id,
                            core_id=core_id, broadcast=broadcast)
                returnValue(DispatchError(StatusCode.INVALID_ARGUMENT))

        except Exception as e:
            log.exception('remote-dispatch-exception', e=e)
            returnValue(DispatchError(StatusCode.UNKNOWN))

    def get_core_id_from_instance_id(self, instance_id):
        """
        :param instance_id: instance name
        :return: core id of that instance
        """
        if instance_id == self.instance_id:
            return self.core_store_id
        for id, instance in self.peers_map.iteritems():
            if instance['id'] == instance_id:
                return id

    def get_cluster_instances(self):
        result = []
        result.append(self.instance_id)
        for id, instance in self.peers_map.iteritems():
            result.append(instance['id'])
        return result

    def instance_id_by_logical_device_id(self, logical_device_id):
        log.warning('temp-mapping-logical-device-id')
        # TODO no true dispatchong yet, we blindly map everything to self
        return self.instance_id

    def instance_id_by_device_id(self, device_id):
        log.warning('temp-mapping-logical-device-id')
        # TODO no true dispatchong yet, we blindly map everything to self
        return self.instance_id

    @inlineCallbacks
    def _broadcast_request(self, method_name, request, context):
        # First get local result
        result = self._local_dispatch(self.core_store_id,
                                      method_name,
                                      request,
                                      context)
        # Then get peers results
        log.debug('maps', peers=self.peers_map, grpc=self.grpc_conn_map)
        current_responses = [result]
        for core_id in self.peers_map:
            if core_id == self.core_store_id:
                continue # already processed

            # As a safeguard, check whether the core_id is in the grpc map
            if core_id not in self.grpc_conn_map:
                log.warn('no-grpc-peer-connection', core=core_id)
            elif self.peers_map[core_id] and self.grpc_conn_map[core_id]:
                res = yield self._dispatch_to_peer(core_id,
                                                   method_name,
                                                   request,
                                                   context)
                if isinstance(res, DispatchError):
                    log.warning('ignoring-peer',
                                core_id=core_id,
                                error_code=res.error_code)
                elif res not in current_responses:
                    result.MergeFrom(res)
                    current_responses.append(res)
        returnValue(result)

    def _local_dispatch(self, core_id, method_name, request, context):
        log.debug('local-dispatch', core_id=core_id)
        method = getattr(self.local_handler, method_name)
        res = method(request, context=context)
        # log.debug('local-dispatch-result', res=res, context=context)
        log.debug('local-dispatch-result', context=context)
        return res

    @inlineCallbacks
    def _start_tracking_peers(self):
        try:
            while True:
                peers_map = yield registry('coordinator').recv_peers_map()
                log.info('peers-map-changed', peers_map=peers_map)
                yield self.update_grpc_client_map(peers_map)
                self.peers_map = peers_map
        except Exception, e:
            log.exception('exception', e=e)

    @inlineCallbacks
    def update_grpc_client_map(self, peers_map):
        try:
            # 1. Get the list of connection to open and to close
            to_open = dict()
            to_close = set()
            for id, instance in peers_map.iteritems():
                # Check for no change
                if id in self.peers_map and self.peers_map[id] == instance:
                    continue

                if id not in self.peers_map:
                    if instance:
                        to_open[id] = instance['host']
                elif instance:
                    to_open[id] = instance['host']
                    if self.peers_map[id]:
                        to_close.add(id)
                else:
                    if self.peers_map[id]:
                        to_close.add(id)

            # Close connections that are no longer referenced
            old_ids = set(self.peers_map.keys()) - set(peers_map.keys())
            for id in old_ids:
                if self.peers_map[id]:
                    to_close.add(id)

            # 2.  Refresh the grpc connections
            yield self._refresh_grpc_connections(to_open, to_close)
        except Exception, e:
            log.exception('exception', e=e)

    @inlineCallbacks
    def _refresh_grpc_connections(self, to_open, to_close):
        try:
            log.info('grpc-channel-refresh', to_open=to_open,
                     to_close=to_close)

            # Close the unused connection
            for id in to_close:
                if self.grpc_conn_map[id]:
                    # clear connection
                    self._disconnect_from_peer(id)

            # Open the new connections
            for id, host in to_open.iteritems():
                if id in self.grpc_conn_map and self.grpc_conn_map[id]:
                    # clear connection
                    self._disconnect_from_peer(id)
                if host:
                    self.grpc_conn_map[id] = \
                        yield self._connect_to_peer(host, self.grpc_port)

        except Exception, e:
            log.exception('exception', e=e)

    @inlineCallbacks
    def _connect_to_peer(self, host, port):
        try:
            channel = yield grpc.insecure_channel('{}:{}'.format(host, port))
            log.info('grpc-channel-created-with-peer', peer=host)
            returnValue(channel)
        except Exception, e:
            log.exception('exception', e=e)

    def _disconnect_from_peer(self, peer_id):
        try:
            if self.grpc_conn_map[peer_id]:
                # Let garbage collection clear the connect - no API exist to
                # close the connection
                # yield self.grpc_conn_map[peer_id].close()
                self.grpc_conn_map[peer_id] = None
                log.info('grpc-channel-closed-with-peer', peer_id=peer_id)
        except Exception, e:
            log.exception('exception', e=e)
        finally:
            self.grpc_conn_map.pop(peer_id)

    @inlineCallbacks
    def _reconnect_to_peer(self, peer_id):
        try:
            # First disconnect
            yield self._disconnect_from_peer(peer_id)
            # Then reconnect
            peer_instance = self.peers_map.get(peer_id, None)
            if peer_instance:
                self.grpc_conn_map[peer_id] = \
                    yield self._connect_to_peer(peer_instance['host'],
                                                self.grpc_port)
                log.info('reconnected-to-peer', peer_id=peer_id)
                returnValue(True)
            else:
                log.info('peer-unavailable', peer_id=peer_id)
        except Exception, e:
            log.exception('exception', e=e)
        returnValue(False)

    @inlineCallbacks
    def _dispatch_to_peer(self,
                          core_id,
                          method_name,
                          request,
                          context,
                          retry=0):
        """
        Invoke a gRPC call to the remote server and return the response.
        :param core_id:  The voltha instance where this request needs to be sent
        :param method_name: The method name inside the service stub
        :param request: The request protobuf message
        :param context: grprc context
        :param retry: on failure, the number of times to retry.
        :return: The response as a protobuf message
        """
        log.debug('peer-dispatch',
                  core_id=core_id,
                  _method_name=method_name,
                  request=request)

        if core_id not in self.peers_map or not self.peers_map[core_id]:
            log.exception('non-existent-core-id', core_id=core_id,
                          peers_map=self.peers_map)
            return

        try:
            # Always request from the local service when making request to peer
            # Add a long timeout of 15 seconds to balance between:
            #       (1) a query for large amount of data from a peer
            #       (2) an error where the peer is not responding and the
            #           request keeps waiting without getting a grpc
            #           rendez-vous exception.
            stub = VolthaLocalServiceStub
            method = getattr(stub(self.grpc_conn_map[core_id]), method_name)
            response, rendezvous = yield method.with_call(request,
                                                          timeout=15,
                                                          metadata=context.invocation_metadata())
            log.debug('peer-response',
                      core_id=core_id,
                      response=response,
                      rendezvous_metadata=rendezvous.trailing_metadata())
            # TODO:  Should we return the metadata as well
            returnValue(response)
        except grpc._channel._Rendezvous, e:
            code = e.code()
            if code == grpc.StatusCode.UNAVAILABLE:
                # Try to reconnect
                status = yield self._reconnect_to_peer(core_id)
                if status and retry > 0:
                    response = yield self._dispatch_to_peer(core_id,
                                                            method_name,
                                                            request,
                                                            context,
                                                            retry=retry - 1)
                    returnValue(response)
            elif code in (
                    grpc.StatusCode.NOT_FOUND,
                    grpc.StatusCode.INVALID_ARGUMENT,
                    grpc.StatusCode.ALREADY_EXISTS,
                    grpc.StatusCode.UNAUTHENTICATED,
                    grpc.StatusCode.PERMISSION_DENIED):

                pass  # don't log error, these occur naturally

            else:
                log.exception('error-invoke', e=e)

            log.warning('error-from-peer', code=code)
            returnValue(DispatchError(code))
