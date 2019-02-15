import structlog
from voltha.adapters.openolt.openolt_utils import OpenoltUtils
from voltha.protos.device_pb2 import Port
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPS_LINK_DOWN, OFPPF_1GB_FD, \
    ofp_port, \
    ofp_port_stats
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.common_pb2 import OperStatus


class OpenOltDataModel(object):
    log = structlog.get_logger()

    def __init__(self, adapter_agent):
        self.adapter_agent = adapter_agent
        self.log = structlog.get_logger()

    def add_logical_port(self, logical_device_id, device_id, port_no, intf_id,
                         oper_state):
        self.log.info('adding-logical-port', port_no=port_no)

        label = OpenoltUtils.port_name(port_no, Port.ETHERNET_NNI)

        cap = OFPPF_1GB_FD | OFPPF_FIBER
        curr_speed = OFPPF_1GB_FD
        max_speed = OFPPF_1GB_FD

        if oper_state == OperStatus.ACTIVE:
            of_oper_state = OFPPS_LIVE
        else:
            of_oper_state = OFPPS_LINK_DOWN

        ofp = ofp_port(
            port_no=port_no,
            hw_addr=mac_str_to_tuple(
                OpenoltUtils.make_mac_from_port_no(port_no)),
            name=label, config=0, state=of_oper_state, curr=cap,
            advertised=cap, peer=cap, curr_speed=curr_speed,
            max_speed=max_speed)

        ofp_stats = ofp_port_stats(port_no=port_no)

        logical_port = LogicalPort(
            id=label, ofp_port=ofp, device_id=device_id,
            device_port_no=port_no, root_port=True,
            ofp_port_stats=ofp_stats)

        self.adapter_agent.add_logical_port(logical_device_id, logical_port)
