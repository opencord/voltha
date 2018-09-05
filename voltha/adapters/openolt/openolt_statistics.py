#
# Copyright 2018 the original author or authors.
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
#
from voltha.protos.events_pb2 import KpiEvent, MetricValuePairs
from voltha.protos.events_pb2 import KpiEventType
import voltha.adapters.openolt.openolt_platform as platform
from voltha.extensions.kpi.olt.olt_pm_metrics import OltPmMetrics
from voltha.protos.device_pb2 import PmConfig, PmConfigs, PmGroupConfig
from voltha.adapters.openolt.nni_port import NniPort
from voltha.adapters.openolt.pon_port import PonPort
from voltha.protos.device_pb2 import Port
from twisted.internet import reactor, defer


class OpenOltStatisticsMgr(object):
    def __init__(self, openolt_device, log, **kargs):

        """
        kargs are used to pass debugging flags at this time.
        :param openolt_device:
        :param log:
        :param kargs:
        """
        self.device = openolt_device
        self.log = log
        # Northbound and Southbound ports
        # added to initialize the pm_metrics
        self.northbound_ports = self.init_ports(type="nni")
        self.southbound_ports = self.init_ports(type='pon')

        self.pm_metrics = None
        # The following can be used to allow a standalone test routine to start
        # the metrics independently
        self.metrics_init = kargs.pop("metrics_init", True)
        if self.metrics_init == True:
            self.init_pm_metrics()

    def init_pm_metrics(self):
        # Setup PM configuration for this device
        if self.pm_metrics is None:
            try:
                self.device.reason = 'setting up Performance Monitoring configuration'
                kwargs = {
                    'nni-ports': self.northbound_ports.values(),
                    'pon-ports': self.southbound_ports.values()
                }
                self.pm_metrics = OltPmMetrics(self.device.adapter_agent, self.device.device_id,
                                               self.device.logical_device_id,
                                               grouped=True, freq_override=False,
                                               **kwargs)
                """
                    override the default naming structures in the OltPmMetrics class.
                    This is being done until the protos can be modified in the BAL driver
                    
                """
                self.pm_metrics.nni_pm_names = (self.get_openolt_port_pm_names())['nni_pm_names']
                self.pm_metrics.nni_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                                 for (m, t) in self.pm_metrics.nni_pm_names}

                self.pm_metrics.pon_pm_names = (self.get_openolt_port_pm_names())['pon_pm_names']
                self.pm_metrics.pon_metrics_config = {m: PmConfig(name=m, type=t, enabled=True)
                                                 for (m, t) in self.pm_metrics.pon_pm_names}
                pm_config = self.pm_metrics.make_proto()
                self.log.info("initial-pm-config", pm_config=pm_config)
                self.device.adapter_agent.update_device_pm_config(pm_config, init=True)
                # Start collecting stats from the device after a brief pause
                reactor.callLater(10, self.pm_metrics.start_collector)
            except Exception as e:
                self.log.exception('pm-setup', e=e)

    def port_statistics_indication(self, port_stats):
        # self.log.info('port-stats-collected', stats=port_stats)
        self.ports_statistics_kpis(port_stats)
        #FIXME: etcd problem, do not update objects for now

        #
        #
        # #FIXME : only the first uplink is a logical port
        # if port_stats.intf_id == 128:
        #     # ONOS update
        #     self.update_logical_port_stats(port_stats)
        # # FIXME: Discard other uplinks, they do not exist as an object
        # if port_stats.intf_id in [129, 130, 131]:
        #     self.log.debug('those uplinks are not created')
        #     return
        # # update port object stats
        # port = self.device.adapter_agent.get_port(self.device.device_id,
        #     port_no=port_stats.intf_id)
        #
        # if port is None:
        #     self.log.warn('port associated with this stats does not exist')
        #     return
        #
        # port.rx_packets = port_stats.rx_packets
        # port.rx_bytes = port_stats.rx_bytes
        # port.rx_errors = port_stats.rx_error_packets
        # port.tx_packets = port_stats.tx_packets
        # port.tx_bytes = port_stats.tx_bytes
        # port.tx_errors = port_stats.tx_error_packets
        #
        # # Add port does an update if port exists
        # self.device.adapter_agent.add_port(self.device.device_id, port)

    def flow_statistics_indication(self, flow_stats):
        self.log.info('flow-stats-collected', stats=flow_stats)
        # TODO: send to kafka ?
        # FIXME: etcd problem, do not update objects for now
        # # UNTESTED : the openolt driver does not yet provide flow stats
        # self.device.adapter_agent.update_flow_stats(
        #       self.device.logical_device_id,
        #       flow_id=flow_stats.flow_id, packet_count=flow_stats.tx_packets,
        #       byte_count=flow_stats.tx_bytes)

    def ports_statistics_kpis(self, port_stats):
        """
        map the port stats values into a dictionary
        Create a kpoEvent and publish to Kafka

        :param port_stats:
        :return:
        """

        try:
            intf_id = port_stats.intf_id

            if 128 < intf_id < 133 :
                """
                for this release we are only interested in intf_id 128 for Northbound.
                we are not using 129, 132
                """
                return
            else:

                pm_data = {}
                pm_data["rx_bytes"] = port_stats.rx_bytes
                pm_data["rx_packets"] = port_stats.rx_packets
                pm_data["rx_ucast_packets"] = port_stats.rx_ucast_packets
                pm_data["rx_mcast_packets"] = port_stats.rx_mcast_packets
                pm_data["rx_bcast_packets"] = port_stats.rx_bcast_packets
                pm_data["rx_error_packets"] = port_stats.rx_error_packets
                pm_data["tx_bytes"] = port_stats.tx_bytes
                pm_data["tx_packets"] = port_stats.tx_packets
                pm_data["tx_ucast_packets"] = port_stats.tx_ucast_packets
                pm_data["tx_mcast_packets"] = port_stats.tx_mcast_packets
                pm_data["tx_bcast_packets"] = port_stats.tx_bcast_packets
                pm_data["tx_error_packets"] = port_stats.tx_error_packets
                pm_data["rx_crc_errors"] = port_stats.rx_crc_errors
                pm_data["bip_errors"] = port_stats.bip_errors

                pm_data["intf_id"] = intf_id

                """
                   Based upon the intf_id map to an nni port or a pon port
                    the intf_id is the key to the north or south bound collections
                    
                    Based upon the intf_id the port object (nni_port or pon_port) will
                    have its data attr. updated by the current dataset collected.
                    
                    For prefixing the rule is currently to use the port number and not the intf_id
                    
                """
                #
                # FIXME
                # Currently filter only 128 since the deployment will only be using port 0 / intf_id 128
                if intf_id == 128:
                    self.update_port_object_kpi_data(
                        port_object=self.northbound_ports[port_stats.intf_id], datadict=pm_data)
                else:
                    self.update_port_object_kpi_data(
                        port_object=self.southbound_ports[port_stats.intf_id],datadict=pm_data)
        except Exception as err:
            self.log.exception("Error publishing kpi statistics. ", errmessage=err)

    def update_logical_port_stats(self, port_stats):
        try:
            label = 'nni-{}'.format(port_stats.intf_id)
            logical_port = self.device.adapter_agent.get_logical_port(
                self.device.logical_device_id, label)
        except KeyError as e:
            self.log.warn('logical port was not found, it may not have been '
                          'created yet', exception=e)
            return

        if logical_port is None:
            self.log.error('logical-port-is-None',
                logical_device_id=self.device.logical_device_id, label=label,
                port_stats=port_stats)
            return

        logical_port.ofp_port_stats.rx_packets = port_stats.rx_packets
        logical_port.ofp_port_stats.rx_bytes = port_stats.rx_bytes
        logical_port.ofp_port_stats.tx_packets = port_stats.tx_packets
        logical_port.ofp_port_stats.tx_bytes = port_stats.tx_bytes
        logical_port.ofp_port_stats.rx_errors = port_stats.rx_error_packets
        logical_port.ofp_port_stats.tx_errors = port_stats.tx_error_packets
        logical_port.ofp_port_stats.rx_crc_err = port_stats.rx_crc_errors

        self.log.debug('after-stats-update', port=logical_port)

        self.device.adapter_agent.update_logical_port(
            self.device.logical_device_id, logical_port)

    """
    The following 4 methods customer naming, the generation of the port objects, building of those
    objects and populating new data.   The pm metrics operate on the value that are contained in the Port objects.
    This class updates those port objects with the current data from the grpc indication and 
    post the data on a fixed interval.
    
    """
    def get_openolt_port_pm_names(self):
        """
        This collects a dictionary of the custom port names
        used by the openolt.

        Some of these are the same as the pm names used by the olt_pm_metrics class
        if the set is the same then there is no need to call this method.   However, when
        custom names are used in the protos then the specific names should be pushed into
        the olt_pm_metrics class.

        :return:
        """
        nni_pm_names = {
            ('intf_id', PmConfig.CONTEXT),  # Physical device interface ID/Port number

            ('admin_state', PmConfig.STATE),
            ('oper_status', PmConfig.STATE),
            ('intf_id', PmConfig.STATE),
            ('port_no', PmConfig.GAUGE),
            ('rx_bytes', PmConfig.COUNTER),
            ('rx_packets', PmConfig.COUNTER),
            ('rx_ucast_packets', PmConfig.COUNTER),
            ('rx_mcast_packets', PmConfig.COUNTER),
            ('rx_bcast_packets', PmConfig.COUNTER),
            ('rx_error_packets', PmConfig.COUNTER),
            ('tx_bytes', PmConfig.COUNTER),
            ('tx_packets', PmConfig.COUNTER),
            ('tx_ucast_packets', PmConfig.COUNTER),
            ('tx_mcast_packets', PmConfig.COUNTER),
            ('tx_bcast_packets', PmConfig.COUNTER),
            ('tx_error_packets', PmConfig.COUNTER)
        }
        nni_pm_names_from_kpi_extension = {
            ('intf_id', PmConfig.CONTEXT),  # Physical device interface ID/Port number

            ('admin_state', PmConfig.STATE),
            ('oper_status', PmConfig.STATE),

            ('rx_bytes', PmConfig.COUNTER),
            ('rx_packets', PmConfig.COUNTER),
            ('rx_ucast_packets', PmConfig.COUNTER),
            ('rx_mcast_packets', PmConfig.COUNTER),
            ('rx_bcast_packets', PmConfig.COUNTER),
            ('rx_error_packets', PmConfig.COUNTER),

            ('tx_bytes', PmConfig.COUNTER),
            ('tx_packets', PmConfig.COUNTER),
            ('tx_ucast_packets', PmConfig.COUNTER),
            ('tx_mcast_packets', PmConfig.COUNTER),
            ('tx_bcast_packets', PmConfig.COUNTER),
            ('tx_error_packets', PmConfig.COUNTER),
            ('rx_crc_errors', PmConfig.COUNTER),
            ('bip_errors', PmConfig.COUNTER),
        }

        # pon_names uses same structure as nmi_names with the addition of pon_id to context
        pon_pm_names = {
            ('intf_id', PmConfig.CONTEXT),  # Physical device port number (PON)
            ('pon_id', PmConfig.CONTEXT),  # PON ID (0..n)
            ('port_no', PmConfig.CONTEXT),

            ('admin_state', PmConfig.STATE),
            ('oper_status', PmConfig.STATE),
            ('rx_bytes', PmConfig.COUNTER),
            ('rx_packets', PmConfig.COUNTER),
            ('rx_ucast_packets', PmConfig.COUNTER),
            ('rx_mcast_packets', PmConfig.COUNTER),
            ('rx_bcast_packets', PmConfig.COUNTER),
            ('rx_error_packets', PmConfig.COUNTER),
            ('tx_bytes', PmConfig.COUNTER),
            ('tx_packets', PmConfig.COUNTER),
            ('tx_ucast_packets', PmConfig.COUNTER),
            ('tx_mcast_packets', PmConfig.COUNTER),
            ('tx_bcast_packets', PmConfig.COUNTER),
            ('tx_error_packets', PmConfig.COUNTER)
        }
        pon_pm_names_from_kpi_extension = {
            ('intf_id', PmConfig.CONTEXT),        # Physical device port number (PON)
            ('pon_id', PmConfig.CONTEXT),         # PON ID (0..n)

            ('admin_state', PmConfig.STATE),
            ('oper_status', PmConfig.STATE),
            ('rx_packets', PmConfig.COUNTER),
            ('rx_bytes', PmConfig.COUNTER),
            ('tx_packets', PmConfig.COUNTER),
            ('tx_bytes', PmConfig.COUNTER),
            ('tx_bip_errors', PmConfig.COUNTER),
            ('in_service_onus', PmConfig.GAUGE),
            ('closest_onu_distance', PmConfig.GAUGE)
        }
        onu_pm_names = {
            ('intf_id', PmConfig.CONTEXT),        # Physical device port number (PON)
            ('pon_id', PmConfig.CONTEXT),
            ('onu_id', PmConfig.CONTEXT),

            ('fiber_length', PmConfig.GAUGE),
            ('equalization_delay', PmConfig.GAUGE),
            ('rssi', PmConfig.GAUGE),
        }
        gem_pm_names = {
            ('intf_id', PmConfig.CONTEXT),        # Physical device port number (PON)
            ('pon_id', PmConfig.CONTEXT),
            ('onu_id', PmConfig.CONTEXT),
            ('gem_id', PmConfig.CONTEXT),

            ('alloc_id', PmConfig.GAUGE),
            ('rx_packets', PmConfig.COUNTER),
            ('rx_bytes', PmConfig.COUNTER),
            ('tx_packets', PmConfig.COUNTER),
            ('tx_bytes', PmConfig.COUNTER),
        }
        # Build a dict for the names.  The caller will index to the correct values
        names_dict = {"nni_pm_names": nni_pm_names,
                      "pon_pm_names": pon_pm_names,
                      "pon_pm_names_orig": pon_pm_names_from_kpi_extension,
                      "onu_pm_names": onu_pm_names,
                      "gem_pm_names": gem_pm_names,

                      }

        return names_dict

    def init_ports(self,  device_id=12345, type="nni", log=None):
        """
        This method collects the port objects:  nni and pon that are updated with the
        current data from the OLT

        Both the northbound (nni) and southbound ports are indexed by the interface id (intf_id)
        and NOT the port number. When the port object is instantiated it will contain the intf_id and
        port_no values

        :param type:
        :param device_id:
        :param log:
        :return:
        """
        try:
            if type == "nni":
                nni_ports = {}
                for i in range(0, 1):
                    nni_port = self.build_port_object(i, type='nni')
                    nni_ports[nni_port.intf_id] = nni_port
                return nni_ports
            elif type == "pon":
                pon_ports = {}
                for i in range(0, 16):
                    pon_port = self.build_port_object(i, type="pon")
                    pon_ports[pon_port.intf_id] = pon_port
                return pon_ports
            else:
                self.log.exception("Unmapped port type requested = " , type=type)
                raise Exception("Unmapped port type requested = " + type)

        except Exception as err:
            raise Exception(err)

    def build_port_object(self, port_num, type="nni"):

        try:
            """ 
             This builds a port object which is added to the 
             appropriate northbound or southbound values
            """
            if type == "nni":
                kwargs = {
                    'port_no': port_num,
                    'intf_id': port_num + 128,
                    "device_id": self.device.device_id
                }
                nni_port = NniPort
                port = nni_port(**kwargs)
                return port

            elif type == "pon":
                # PON ports require a different configuration
                #  intf_id and pon_id are currently equal.
                kwargs = {
                    'port_no': port_num,
                    'intf_id': 0x2 << 28 | port_num,
                    'pon-id': 0x2 << 28 | port_num,
                    "device_id": self.device.device_id
                }
                pon_port = PonPort
                port = pon_port(**kwargs)
                return port

            else:
                self.log.exception("Unknown port type")
                raise Exception("Unknown port type")

        except Exception as err:
            self.log.exception("Unknown port type", error=err)
            raise Exception(err)

    def update_port_object_kpi_data(self, port_object, datadict={}):
        """
        This method takes the formatted data the is marshalled from
        the initicator collector and updates the corresponding property by
        attr get and set.

        :param port: The port class to be updated
        :param datadict:
        :return:
        """

        try:
            cur_attr = ""
            if isinstance(port_object, NniPort):
                for k, v in datadict.items():
                    cur_attr = k
                    if hasattr(port_object, k):
                        setattr(port_object, k, v)
            elif isinstance(port_object, PonPort):
                for k, v in datadict.items():
                    cur_attr = k
                    if hasattr(port_object, k):
                        setattr(port_object, k, v)
            else:
                raise Exception("Must be either PON or NNI port.")
            return
        except Exception as err:
            self.log.exception("Caught error updating port data: ", cur_attr=cur_attr, errormsg=err.message)
            raise Exception(err)