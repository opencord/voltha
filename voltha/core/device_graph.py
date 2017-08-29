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

import networkx as nx

from voltha.core.flow_decomposer import RouteHop


class DeviceGraph(object):

    """
    Mixin class to compute routes in the device graph within
    a logical device.
    """

    def compute_routes(self, root_proxy, logical_ports):
        boundary_ports, graph = self._build_graph(root_proxy, logical_ports)
        routes = self._build_routes(boundary_ports, graph, logical_ports)
        return graph, routes

    def _build_graph(self, root_proxy, logical_ports):

        graph = nx.Graph()

        # walk logical device's device and port links to discover full graph
        devices_added = set()  # set of device.id's
        ports_added = set()  # set of (device.id, port_no) tuples
        peer_links = set()

        boundary_ports = dict(
            ((lp.device_id, lp.device_port_no), lp.ofp_port.port_no)
            for lp in logical_ports
        )

        def add_device(device):
            if device.id in devices_added:
                return

            graph.add_node(device.id, device=device)
            devices_added.add(device.id)

            ports = root_proxy.get('/devices/{}/ports'.format(device.id))
            for port in ports:
                port_id = (device.id, port.port_no)
                if port_id not in ports_added:
                    boundary = port_id in boundary_ports
                    graph.add_node(port_id, port=port, boundary=boundary)
                    graph.add_edge(device.id, port_id)
                for peer in port.peers:
                    if peer.device_id not in devices_added:
                        peer_device = root_proxy.get(
                            '/devices/{}'.format(peer.device_id))
                        add_device(peer_device)
                    else:
                        peer_port_id = (peer.device_id, peer.port_no)
                        if port_id < peer_port_id:
                            peer_link = (port_id, peer_port_id)
                        else:
                            peer_link = (peer_port_id, port_id)
                        if peer_link not in peer_links:
                            graph.add_edge(*peer_link)
                            peer_links.add(peer_link)

        for logical_port in logical_ports:
            device_id = logical_port.device_id
            device = root_proxy.get('/devices/{}'.format(device_id))
            add_device(device)

        return boundary_ports, graph

    def _build_routes(self, boundary_ports, graph, logical_ports):

        root_ports = dict((lp.ofp_port.port_no, lp.root_port)
                          for lp in logical_ports if lp.root_port == True)

        routes = {}

        for source, source_port_no in boundary_ports.iteritems():
            for target, target_port_no in boundary_ports.iteritems():

                if source is target:
                    continue

                # Ignore NNI - NNI routes
                if source_port_no in root_ports \
                        and target_port_no in root_ports:
                    continue

                # Ignore UNI - UNI routes
                if source_port_no not in root_ports \
                        and target_port_no not in root_ports:
                    continue

                path = nx.shortest_path(graph, source, target)

                # number of nodes in valid paths is always multiple of 3
                if len(path) % 3:
                    continue

                # in fact, we currently deal with single fan-out networks,
                # so the number of hops is always 6
                assert len(path) == 6

                ingress_input_port, ingress_device, ingress_output_port, \
                egress_input_port, egress_device, egress_output_port = path

                ingress_hop = RouteHop(
                    device=graph.node[ingress_device]['device'],
                    ingress_port=graph.node[ingress_input_port]['port'],
                    egress_port=graph.node[ingress_output_port]['port']
                )
                egress_hop = RouteHop(
                    device=graph.node[egress_device]['device'],
                    ingress_port=graph.node[egress_input_port]['port'],
                    egress_port=graph.node[egress_output_port]['port']
                )

                routes[(source_port_no, target_port_no)] = [
                    ingress_hop, egress_hop
                ]

        return routes

