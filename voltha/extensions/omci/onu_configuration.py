#
# Copyright 2018 the original author or authors.
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

from voltha.protos.device_pb2 import Image
from omci_entities import *
from database.mib_db_api import *
from enum import IntEnum


class OMCCVersion(IntEnum):
    Unknown                 = 0     # Unknown or unsupported version
    G_984_4                 = 0x80  # (06/04)
    G_984_4_2005_Amd_1      = 0x81  # Amd.1 (06/05)
    G_984_4_2006_Amd_2      = 0x82  # Amd.2 (03/06)
    G_984_4_2006_Amd_3      = 0x83  # Amd.3 (12/06)
    G_984_4_2008            = 0x84  # (02/08)
    G_984_4_2009_Amd_1      = 0x85  # Amd.1 (06/09)
    G_984_4_2009_Amd_2_Base = 0x86  # Amd.2 (2009)  Baseline message set only, w/o the extended message set option
    G_984_4_2009_Amd_2      = 0x96  # Amd.2 (2009)  Extended message set option +  baseline message set.
    G_988_2010_Base         = 0xA0  # (2010) Baseline message set only, w/o the extended message set option
    G_988_2011_Amd_1_Base   = 0xA1  # Amd.1 (2011) Baseline message set only
    G_988_2012_Amd_2_Base   = 0xA2  # Amd.2 (2012) Baseline message set only
    G_988_2012_Base         = 0xA3  # (2012) Baseline message set only
    G_988_2010              = 0xB0  # (2010) Baseline and extended message set
    G_988_2011_Amd_1        = 0xB1  # Amd.1 (2011) Baseline and extended message set
    G_988_2012_Amd_2        = 0xB2  # Amd.2 (2012) Baseline and extended message set
    G_988_2012              = 0xB3  # (2012)Baseline and extended message set

    @staticmethod
    def values():
        return {OMCCVersion[member].value for member in OMCCVersion.__members__.keys()}

    @staticmethod
    def to_enum(value):
        return next((v for k, v in OMCCVersion.__members__.items()
                     if v.value == value), OMCCVersion.Unknown)


class OnuConfiguration(object):
    """
    Utility class to query OMCI MIB Database for various ONU/OMCI Configuration
    and capabilties. These capabilities revolve around read-only MEs discovered
    during the MIB Upload process.

    There is also a 'omci_onu_capabilities' State Machine and an
    'onu_capabilities_task.py' OMCI Task that will query the ONU, via the
    OMCI (ME#287) Managed entity to get the full list of supported OMCI ME's
    and available actions/message-types supported.

    NOTE: Currently this class is optimized/tested for ONUs that support the
          OpenOMCI implementation.
    """
    def __init__(self, omci_agent, device_id):
        """
        Initialize this instance of the OnuConfiguration class

        :param omci_agent: (OpenOMCIAgent) agent reference
        :param device_id: (str) ONU Device ID

        :raises KeyError: If ONU Device is not registered with OpenOMCI
        """
        self.log = structlog.get_logger(device_id=device_id)
        self._device_id = device_id
        self._onu_device = omci_agent.get_device(device_id)

        # The capabilities
        self._attributes = None
        self.reset()

    def _get_capability(self, attr, class_id, instance_id=None):
        """
        Get the OMCI capabilities for this device

        :param attr: (str) OnuConfiguration attribute field
        :param class_id: (int) ME Class ID
        :param instance_id: (int) Instance ID. If not provided, all instances of the
                            specified class ID are returned if present in the DB.

        :return: (dict) Class and/or Instances. None is returned if the CLASS is not present
        """
        try:
            assert self._onu_device.mib_synchronizer.last_mib_db_sync is not None, \
                'MIB Database for ONU {} has never been synchronized'.format(self._device_id)

            # Get the requested information
            if self._attributes[attr] is None:
                value = self._onu_device.query_mib(class_id, instance_id=instance_id)

                if isinstance(value, dict) and len(value) > 0:
                    self._attributes[attr] = value

            return self._attributes[attr]

        except Exception as e:
            self.log.exception('onu-capabilities', e=e, class_id=class_id,
                               instance_id=instance_id)
            raise

    def reset(self):
        """
        Reset the cached database entries to None.  This method should be
        called after any communications loss to the ONU (reboot, PON down, ...)
        in case a new software load with different capabilities is available.
        """
        self._attributes = {
            '_ont_g': None,
            '_ont_2g': None,
            '_ani_g': None,
            '_uni_g': None,
            '_cardholder': None,
            '_circuit_pack': None,
            '_software': None,
            '_pptp': None,
            '_veip': None
        }

    @property
    def version(self):
        """
        This attribute identifies the version of the ONU as defined by the vendor
        """
        ontg = self._get_capability('_ont_g', OntG.class_id, 0)
        if ontg is None or ATTRIBUTES_KEY not in ontg:
            return None

        return ontg[ATTRIBUTES_KEY].get('version')

    @property
    def serial_number(self):
        """
        The serial number is unique for each ONU
        """
        ontg = self._get_capability('_ont_g', OntG.class_id, 0)
        if ontg is None or ATTRIBUTES_KEY not in ontg:
            return None

        return ontg[ATTRIBUTES_KEY].get('serial_number')

    @property
    def traffic_management_option(self):
        """
        This attribute identifies the upstream traffic management function
        implemented in the ONU. There are three options:

            0 Priority controlled and flexibly scheduled upstream traffic. The traffic
              scheduler and priority queue mechanism are used for upstream traffic.

            1 Rate controlled upstream traffic. The maximum upstream traffic of each
              individual connection is guaranteed by shaping.

            2 Priority and rate controlled. The traffic scheduler and priority queue
              mechanism are used for upstream traffic. The maximum upstream traffic
              of each individual connection is guaranteed by shaping.
        """
        ontg = self._get_capability('_ont_g', OntG.class_id, 0)
        if ontg is None or ATTRIBUTES_KEY not in ontg:
            return None

        return ontg[ATTRIBUTES_KEY].get('traffic_management_options')

    @property
    def onu_survival_time(self):
        """
        This attribute indicates the minimum guaranteed time in milliseconds
        between the loss of external power and the silence of the ONU. This does not
        include survival time attributable to a backup battery. The value zero implies that
        the actual time is not known.

        Optional
        """
        ontg = self._get_capability('_ont_g', OntG.class_id, 0)
        if ontg is None or ATTRIBUTES_KEY not in ontg:
            return None

        return ontg[ATTRIBUTES_KEY].get('ont_survival_time', 0)

    @property
    def equipment_id(self):
        """
        This attribute may be used to identify the specific type of ONU. In some
        environments, this attribute may include the equipment CLEI code.
        """
        ont2g = self._get_capability('_ont_2g', Ont2G.class_id, 0)
        if ont2g is None or ATTRIBUTES_KEY not in ont2g:
            return None

        return ont2g[ATTRIBUTES_KEY].get('equipment_id')

    @property
    def omcc_version(self):
        """
        This attribute identifies the version of the OMCC protocol being used by the
        ONU. This allows the OLT to manage a network with ONUs that support different
        OMCC versions. Release levels of [ITU-T G.984.4] are supported with code
        points of the form 0x8y and 0x9y, where y is a hexadecimal digit in the range
        0..F.  Support for continuing revisions of this Recommendation is defined in
        the 0xAy range.
        """
        ont2g = self._get_capability('_ont_2g', Ont2G.class_id, 0)
        if ont2g is None or ATTRIBUTES_KEY not in ont2g:
            return None

        return OMCCVersion.to_enum(ont2g[ATTRIBUTES_KEY].get('omcc_version', 0))

    @property
    def vendor_product_code(self):
        """
        This attribute contains a vendor-specific product code for the ONU
        """
        ont2g = self._get_capability('_ont_2g', Ont2G.class_id, 0)
        if ont2g is None or ATTRIBUTES_KEY not in ont2g:
            return None

        return ont2g[ATTRIBUTES_KEY].get('vendor_product_code')

    @property
    def total_priority_queues(self):
        """
        This attribute reports the total number of upstream priority queues
        that are not associated with a circuit pack, but with the ONU in its entirety
        """
        ont2g = self._get_capability('_ont_2g', Ont2G.class_id, 0)
        if ont2g is None or ATTRIBUTES_KEY not in ont2g:
            return None

        return ont2g[ATTRIBUTES_KEY].get('total_priority_queue_number')

    @property
    def total_traffic_schedulers(self):
        """
        This attribute reports the total number of traffic schedulers that
        are not associated with a circuit pack, but with the ONU in its entirety.
        """
        ont2g = self._get_capability('_ont_2g', Ont2G.class_id, 0)
        if ont2g is None or ATTRIBUTES_KEY not in ont2g:
            return None

        return ont2g[ATTRIBUTES_KEY].get('total_traffic_scheduler_number')

    @property
    def total_gem_ports(self):
        """
        This attribute reports the total number of GEM port-IDs supported
        by the ONU.
        """
        ont2g = self._get_capability('_ont_2g', Ont2G.class_id, 0)
        if ont2g is None or ATTRIBUTES_KEY not in ont2g:
            return None

        return ont2g[ATTRIBUTES_KEY].get('total_gem_port_id_number')

    @property
    def uptime(self):
        """
        This attribute counts 10 ms intervals since the ONU was last initialized.
        It rolls over to 0 when full
        """
        ont2g = self._get_capability('_ont_2g', Ont2G.class_id, 0)
        if ont2g is None or ATTRIBUTES_KEY not in ont2g:
            return None

        return ont2g[ATTRIBUTES_KEY].get('sys_uptime')

    @property
    def connectivity_capability(self):
        """
        This attribute indicates the Ethernet connectivity models that the ONU
        can support. The value 0 indicates that the capability is not supported; 1 signifies
        support.

             Bit    Model [Figure reference ITU-T 988]
              1     (LSB) N:1 bridging, Figure 8.2.2-3
              2     1:M mapping, Figure 8.2.2-4
              3     1:P filtering, Figure 8.2.2-5
              4     N:M bridge-mapping, Figure 8.2.2-6
              5     1:MP map-filtering, Figure 8.2.2-7
              6     N:P bridge-filtering, Figure 8.2.2-8
              7  to refer to    N:MP bridge-map-filtering, Figure 8.2.2-9
            8...16  Reserved
        """
        ont2g = self._get_capability('_ont_2g', Ont2G.class_id, 0)
        if ont2g is None or ATTRIBUTES_KEY not in ont2g:
            return None

        return ont2g[ATTRIBUTES_KEY].get('connectivity_capability')

    @property
    def qos_configuration_flexibility(self):
        """
        This attribute reports whether various managed entities in the
        ONU are fixed by the ONU's architecture or whether they are configurable. For
        backward compatibility, and if the ONU does not support this attribute, all such
        attributes are understood to be hard-wired.

            Bit      Interpretation when bit value = 1
             1 (LSB) Priority queue ME: Port field of related port attribute is
                     read-write and can point to any T-CONT or UNI port in the
                     same slot
             2       Priority queue ME: The traffic scheduler pointer is permitted
                     to refer to any other traffic scheduler in the same slot
             3       Traffic scheduler ME: T-CONT pointer is read-write
             4       Traffic scheduler ME: Policy attribute is read-write
             5       T-CONT ME: Policy attribute is read-write
             6       Priority queue ME: Priority field of related port attribute is
                     read-write
             7..16   Reserved
        """
        ont2g = self._get_capability('_ont_2g', Ont2G.class_id, 0)
        if ont2g is None or ATTRIBUTES_KEY not in ont2g:
            return None

        return ont2g[ATTRIBUTES_KEY].get('qos_configuration_flexibility')

    @property
    def priority_queue_scale_factor(self):
        """
        This specifies the scale factor of several attributes of the priority
        queue managed entity of section 5.2.8
        """
        ont2g = self._get_capability('_ont_2g', Ont2G.class_id, 0)
        if ont2g is None or ATTRIBUTES_KEY not in ont2g:
            return None

        return ont2g[ATTRIBUTES_KEY].get('priority_queue_scale_factor', 1)

    @property
    def cardholder_entities(self):
        """
        Return a dictionary containing some overall information on the CardHolder
        instances for this ONU.
        """
        ch = self._get_capability('_cardholder', Cardholder.class_id)
        results = dict()

        if ch is not None:
            for inst, inst_data in ch.items():
                if isinstance(inst, int):
                    results[inst] = {
                        'entity-id':              inst,
                        'is-single-piece':        inst >= 256,
                        'slot-number':            inst & 0xff,
                        'actual-plug-in-type':    inst_data[ATTRIBUTES_KEY].get('actual_plugin_unit_type', 0),
                        'actual-equipment-id':    inst_data[ATTRIBUTES_KEY].get('actual_equipment_id', 0),
                        'protection-profile-ptr': inst_data[ATTRIBUTES_KEY].get('protection_profile_pointer', 0),
                    }
        return results if len(results) else None

    @property
    def circuitpack_entities(self):
        """
        This specifies the scale factor of several attributes of the priority
        queue managed entity of section 5.2.8
        """
        cp = self._get_capability('_circuit_pack', CircuitPack.class_id)
        results = dict()

        if cp is not None:
            for inst, inst_data in cp.items():
                if isinstance(inst, int):
                    results[inst] = {
                        'entity-id': inst,
                        'number-of-ports': inst_data[ATTRIBUTES_KEY].get('number_of_ports', 0),
                        'serial-number': inst_data[ATTRIBUTES_KEY].get('serial_number', 0),
                        'version': inst_data[ATTRIBUTES_KEY].get('version', 0),
                        'vendor-id': inst_data[ATTRIBUTES_KEY].get('vendor_id', 0),
                        'total-tcont-count': inst_data[ATTRIBUTES_KEY].get('total_tcont_buffer_number', 0),
                        'total-priority-queue-count': inst_data[ATTRIBUTES_KEY].get('total_priority_queue_number', 0),
                        'total-traffic-sched-count': inst_data[ATTRIBUTES_KEY].get('total_traffic_scheduler_number', 0),
                    }

        return results if len(results) else None

    @property
    def software_images(self):
        """
        Get a list of software image information for the ONU.  The information is provided
        so that it may be directly added to the protobuf Device information software list.
        """
        sw = self._get_capability('_software', SoftwareImage.class_id)
        images = list()

        if sw is not None:
            for inst, inst_data in sw.items():
                if isinstance(inst, int):
                    is_active = inst_data[ATTRIBUTES_KEY].get('is_active', False)

                    images.append(Image(name='running-revision' if is_active else 'candidate-revision',
                                        version=str(inst_data[ATTRIBUTES_KEY].get('version',
                                                                                  'Not Available').rstrip('\0')),
                                        is_active=is_active,
                                        is_committed=inst_data[ATTRIBUTES_KEY].get('is_committed',
                                                                                   False),
                                        is_valid=inst_data[ATTRIBUTES_KEY].get('is_valid',
                                                                               False),
                                        install_datetime='Not Available',
                                        hash=str(inst_data[ATTRIBUTES_KEY].get('image_hash',
                                                                               'Not Available').rstrip('\0'))))
        return images if len(images) else None

    @property
    def ani_g_entities(self):
        """
        This managed entity organizes data associated with each access network
        interface supported by a G-PON ONU. The ONU automatically creates one
        instance of this managed entity for each PON physical port.
        """
        ag = self._get_capability('_ani_g', AniG.class_id)
        results = dict()

        if ag is not None:
            for inst, inst_data in ag.items():
                if isinstance(inst, int):
                    results[inst] = {
                        'entity-id':               inst,
                        'slot-number':             (inst >> 8) & 0xff,
                        'port-number':             inst & 0xff,
                        'total-tcont-count':       inst_data[ATTRIBUTES_KEY].get('total_tcont_number', 0),
                        'piggyback-dba-reporting': inst_data[ATTRIBUTES_KEY].get('piggyback_dba_reporting', 0),
                    }
        return results if len(results) else None

    @property
    def uni_g_entities(self):
        """
        This managed entity organizes data associated with user network interfaces
        (UNIs) supported by GEM. One instance of the UNI-G managed entity exists
        for each UNI supported by the ONU.

        The ONU automatically creates or deletes instances of this managed entity
        upon the creation or deletion of a real or virtual circuit pack managed
        entity, one per port.
        """
        ug = self._get_capability('_uni_g', UniG.class_id)
        results = dict()

        if ug is not None:
            for inst, inst_data in ug.items():
                if isinstance(inst, int):
                    results[inst] = {
                        'entity-id':               inst,
                        'management-capability':   inst_data[ATTRIBUTES_KEY].get('management_capability', 0)
                    }
        return results if len(results) else None

    @property
    def pptp_entities(self):
        """
        Returns discovered PPTP Ethernet entities.  TODO more detail here
        """
        pptp = self._get_capability('_pptp', PptpEthernetUni.class_id)
        results = dict()

        if pptp is not None:
            for inst, inst_data in pptp.items():
                if isinstance(inst, int):
                    results[inst] = {
                        'entity-id':                inst,
                        'expected-type':            inst_data[ATTRIBUTES_KEY].get('expected_type', 0),
                        'sensed-type':              inst_data[ATTRIBUTES_KEY].get('sensed_type', 0),
                        'autodetection-config':     inst_data[ATTRIBUTES_KEY].get('autodetection_config', 0),
                        'ethernet-loopback-config': inst_data[ATTRIBUTES_KEY].get('ethernet_loopback_config', 0),
                        'administrative-state':     inst_data[ATTRIBUTES_KEY].get('administrative_state', 0),
                        'operational-state':        inst_data[ATTRIBUTES_KEY].get('operational_state', 0),
                        'config-ind':               inst_data[ATTRIBUTES_KEY].get('config_ind', 0),
                        'max-frame-size':           inst_data[ATTRIBUTES_KEY].get('max_frame_size', 0),
                        'dte-dce-ind':              inst_data[ATTRIBUTES_KEY].get('dte_dce_ind', 0),
                        'pause-time':               inst_data[ATTRIBUTES_KEY].get('pause_time', 0),
                        'bridged-ip-ind':           inst_data[ATTRIBUTES_KEY].get('bridged_ip_ind', 0),
                        'arc':                      inst_data[ATTRIBUTES_KEY].get('arc', 0),
                        'arc-interval':             inst_data[ATTRIBUTES_KEY].get('arc_interval', 0),
                        'pppoe-filter':             inst_data[ATTRIBUTES_KEY].get('ppoe_filter', 0),
                        'power-control':            inst_data[ATTRIBUTES_KEY].get('power_control', 0)
                    }
        return results if len(results) else None

    @property
    def veip_entities(self):
        """
        Returns discovered VEIP entities.  TODO more detail here
        """
        veip = self._get_capability('_veip', VeipUni.class_id)
        results = dict()

        if veip is not None:
            for inst, inst_data in veip.items():
                if isinstance(inst, int):
                    results[inst] = {
                        'entity-id':                inst,
                        'administrative-state':     inst_data[ATTRIBUTES_KEY].get('administrative_state', 0),
                        'operational-state':        inst_data[ATTRIBUTES_KEY].get('operational_state', 0),
                        'interdomain-name':         inst_data[ATTRIBUTES_KEY].get('interdomain_name', ""),
                        'tcp-udp-pointer':          inst_data[ATTRIBUTES_KEY].get('tcp_udp_pointer', 0),
                        'iana-assigned-port':       inst_data[ATTRIBUTES_KEY].get('iana_assigned_port', 0)
                    }
        return results if len(results) else None
