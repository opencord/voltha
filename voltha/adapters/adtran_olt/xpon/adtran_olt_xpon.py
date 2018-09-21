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

import structlog
from adtran_xpon import AdtranXPON
from voltha.protos.bbf_fiber_base_pb2 import \
    ChannelgroupConfig, ChannelpartitionConfig, ChannelpairConfig, \
    ChannelterminationConfig, OntaniConfig, VOntaniConfig, VEnetConfig
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from voltha.protos.bbf_fiber_multicast_gemport_body_pb2 import \
    MulticastGemportsConfigData
from voltha.protos.bbf_fiber_multicast_distribution_set_body_pb2 import \
    MulticastDistributionSetData
import voltha.adapters.adtran_olt.adtranolt_platform as platform

log = structlog.get_logger()


# SEBA
class AdtranOltXPON(AdtranXPON):
    """
    Class to for OLT and XPON operations
    """
    def __init__(self, **kwargs):
        super(AdtranOltXPON, self).__init__(**kwargs)

        # xPON config dictionaries
        self._channel_groups = {}         # Name -> dict
        self._channel_partitions = {}     # Name -> dict
        self._channel_pairs = {}          # Name -> dict
        self._channel_terminations = {}   # Name -> dict

    @property
    def channel_terminations(self):
        return self._channel_terminations

    @property
    def channel_groups(self):
        return self._channel_groups

    @property
    def channel_pairs(self):
        return self._channel_pairs

    @property
    def channel_partitions(self):
        return self._channel_partitions

    # SEBA
    def get_device_profile_info(self, pon, serial_number):
        """ TODO: For now, push into legacy xPON structures.  Clean up once we deprecate xPON and remove it"""
        pon_id = pon.pon_id
        if pon_id not in self._cached_xpon_pon_info:
            venets = dict()
            v_ont_anis = dict()
            ont_anis = dict()
            tconts = dict()
            gem_ports = dict()
            groups = {
                "group-{}".format(pon_id):
                    {
                        'name'          : "group-{}".format(pon_id),
                        'system-id'     : '000000',
                        'enabled'       : True,
                        'polling-period': 200
                    }
            }
            partitions = {
                "partition-{}".format(pon_id):
                    {
                        'name'                       : "partition-{}".format(pon_id),
                        'enabled'                    : True,
                        'fec-downstream'             : True,
                        'mcast-aes'                  : False,
                        'channel-group'              : 'group-{}'.format(pon_id),
                        'authentication-method'      : 'serial-number',
                        'differential-fiber-distance': 20
                    }
            }
            pairs = {
                'pon-{}'.format(pon_id):
                    {
                        'name'             : 'pon-{}.format(pon_id)',
                        'enabled'          : True,
                        'channel-group'    : 'group-{}'.format(pon_id),
                        'channel-partition': 'partition-{}'.format(pon_id),
                        'line-rate'        : 'down_10_up_10',

                    }
            }
            terminations = {
                'channel-termination {}'.format(pon_id):
                {
                    'name'           : 'channel-termination {}'.format(pon_id),
                    'enabled'        : True,
                    'channel-pair'   : 'pon-{}'.format(pon_id),
                    'xgpon-ponid'    : pon_id,
                    'xgs-ponid'      : pon_id,
                    'ber-calc-period': 10,
                }
            }
            # Save this to the cache
            self._cached_xpon_pon_info[pon_id] = {
                'channel-terminations': terminations,
                'channel-pairs'       : pairs,
                'channel-partitions'  : partitions,
                'channel-groups'      : groups,
                'vont-anis'           : v_ont_anis,
                'ont-anis'            : ont_anis,
                'v-enets'             : venets,
                'tconts'              : tconts,
                'gem-ports'           : gem_ports
            }
        # Now update vont_ani and ont_ani information if needed
        xpon_info = self._cached_xpon_pon_info[pon_id]

        vont_ani_info = next((info for _, info in xpon_info['vont-anis'].items()
                             if info.get('expected-serial-number') == serial_number), None)
        # New ONU?
        activate_onu = vont_ani_info is None

        if activate_onu:
            onu_id = pon.get_next_onu_id
            name = 'customer-000000-{}-{}'.format(pon_id, onu_id)
            vont_ani_info = {
                'name'                    : name,
                'enabled'                 : True,
                'description'             : '',
                'onu-id'                  : onu_id,
                'expected-serial-number'  : serial_number,
                'expected-registration-id': '',                         # TODO: How about this?
                'channel-partition'       : 'partition-{}'.format(pon_id),
                'upstream-channel-speed'  : 10000000000,
                'preferred-channel-pair'  : 'pon-{}'.format(pon_id)
            }
            ont_ani_info = {
                'name':             name,
                'description':      '',
                'enabled':          True,
                'upstream-fec':     True,
                'mgnt-gemport-aes': False
            }
            xpon_info['vont-anis'][name] = vont_ani_info
            xpon_info['ont-anis'][name] = ont_ani_info

            from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
            from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import TrafficDescriptorProfileData
            from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData

            tcont = TcontsConfigData()
            tcont.name = 'tcont-{}-{}-data'.format(pon_id, onu_id)
            tcont.alloc_id = platform.mk_alloc_id(pon_id, onu_id)

            traffic_desc = TrafficDescriptorProfileData(name='BestEffort',
                                                        fixed_bandwidth=0,
                                                        assured_bandwidth=0,
                                                        maximum_bandwidth=10000000000,
                                                        priority=0,
                                                        weight=0,
                                                        additional_bw_eligibility_indicator=0)
            tc = {
                'name': tcont.name,
                'alloc-id': tcont.alloc_id,
                'vont-ani': name,
                'td-ref': {                    # TODO: This should be the TD Name and the TD installed in xpon cache
                    'name': traffic_desc.name,
                    'fixed-bandwidth': traffic_desc.fixed_bandwidth,
                    'assured-bandwidth': traffic_desc.assured_bandwidth,
                    'maximum-bandwidth': traffic_desc.maximum_bandwidth,
                    'priority': traffic_desc.priority,
                    'weight': traffic_desc.weight,
                    'additional-bw-eligibility-indicator': 0,
                    'data': traffic_desc
                },
                'data': tcont
            }
            from olt_tcont import OltTCont
            from olt_traffic_descriptor import OltTrafficDescriptor
            tc['object'] = OltTCont.create(tc, OltTrafficDescriptor.create(tc['td-ref']))
            xpon_info['tconts'][tcont.name] = tc['object']

            # gem port creation (this initial one is for untagged ONU data support / EAPOL)
            gem_port, gp = self.create_gem_port(pon_id, onu_id, 0, tcont, untagged=True)
            gem_ports = [gem_port]

            from olt_gem_port import OltGemPort
            gp['object'] = OltGemPort.create(self, gp)
            xpon_info['gem-ports'][gem_port.name] = gp['object']

            # Now create the User-Data GEM-Ports
            nub_priorities = 1                          # TODO: Pull form tech-profile later
            for index in range(1, nub_priorities + 1):
                gem_port, gp = self.create_gem_port(pon_id, onu_id, index, tcont)
                gem_ports.append(gem_port)

                from olt_gem_port import OltGemPort
                gp['object'] = OltGemPort.create(self, gp)
                xpon_info['gem-ports'][gem_port.name] = gp['object']

            self.create_tcont(tcont, traffic_desc)
            for gem_port in gem_ports:
                self.xpon_create(gem_port)

        return xpon_info, activate_onu

    def create_gem_port(self, pon_id, onu_id, index, tcont, untagged=False):
        # gem port creation (this initial one is for untagged ONU data support / EAPOL)
        gem_port = GemportsConfigData()
        gem_port.gemport_id = platform.mk_gemport_id(pon_id, onu_id, idx=index)
        if untagged:
            gem_port.name = 'gemport-{}-{}-untagged-{}'.format(pon_id, onu_id, gem_port.gemport_id)
        else:
            gem_port.name = 'gemport-{}-{}-data-{}'.format(pon_id, onu_id, gem_port.gemport_id)

        gem_port.tcont_ref = tcont.name

        gp = {
            'name': gem_port.name,
            'gemport-id': gem_port.gemport_id,
            'tcont-ref': gem_port.tcont_ref,
            'encryption': False,
            'traffic-class': 0,
            'data': gem_port
        }
        return gem_port, gp

    # SEBA
    def get_xpon_info(self, pon_id, pon_id_type='xgs-ponid'):
        """
        Lookup all xPON configuration data for a specific pon-id / channel-termination
        :param pon_id: (int) PON Identifier
        :return: (dict) reduced xPON information for the specific PON port
        """
        if pon_id not in self._cached_xpon_pon_info:
            terminations = {key: val for key, val in self._channel_terminations.iteritems()
                            if val[pon_id_type] == pon_id}

            pair_names = set([term['channel-pair'] for term in terminations.itervalues()])
            pairs = {key: val for key, val in self.channel_pairs.iteritems()
                     if key in pair_names}

            partition_names = set([pair['channel-partition'] for pair in pairs.itervalues()])
            partitions = {key: val for key, val in self.channel_partitions.iteritems()
                          if key in partition_names}

            v_ont_anis = {key: val for key, val in self.v_ont_anis.iteritems()
                          if val['preferred-channel-pair'] in pair_names}
            v_ont_ani_names = set(v_ont_anis.keys())

            ont_anis = {key: val for key, val in self.ont_anis.iteritems()
                        if key in v_ont_ani_names}

            group_names = set(pair['channel-group'] for pair in pairs.itervalues())
            groups = {key: val for key, val in self.channel_groups.iteritems()
                      if key in group_names}

            venets = {key: val for key, val in self.v_enets.iteritems()
                      if val['vont-ani'] in v_ont_ani_names}

            tconts = {key: val['object'] for key, val in self.tconts.iteritems()
                      if val['vont-ani'] in v_ont_ani_names and 'object' in val}
            tcont_names = set(tconts.keys())

            gem_ports = {key: val['object'] for key, val in self.gem_ports.iteritems()
                         if val['tcont-ref'] in tcont_names and 'object' in val}

            self._cached_xpon_pon_info[pon_id] = {
                'channel-terminations': terminations,
                'channel-pairs': pairs,
                'channel-partitions': partitions,
                'channel-groups': groups,
                'vont-anis': v_ont_anis,
                'ont-anis': ont_anis,
                'v-enets': venets,
                'tconts': tconts,
                'gem-ports': gem_ports
            }
        return self._cached_xpon_pon_info[pon_id]

    def get_related_pons(self, item, pon_type='xgs-ponid'):
        pon_ids = set()
        ports = []
        data = item['data']

        if isinstance(data, ChannelgroupConfig):
            group_name = item['name']
            pair_names = {val['name'] for val in self.channel_pairs.itervalues()
                          if val['channel-group'] == group_name}
            pon_ids = {val[pon_type] for val in self.channel_terminations.itervalues()
                       if val['channel-pair'] in pair_names}

        elif isinstance(data, ChannelpartitionConfig):
            part_name = item['name']
            pair_names = {val['name'] for val in self.channel_pairs.itervalues()
                          if val['channel-partition'] == part_name}
            pon_ids = {val[pon_type] for val in self.channel_terminations.itervalues()
                       if val['channel-pair'] in pair_names}

        elif isinstance(data, ChannelpairConfig):
            pair_name = item['name']
            pon_ids = {val[pon_type] for val in self.channel_terminations.itervalues()
                       if val['channel-pair'] == pair_name}

        elif isinstance(data, ChannelterminationConfig):
            pon_ids = [item[pon_type]]

        elif isinstance(data, (OntaniConfig, VOntaniConfig)):
            # ont_ani name == vont_ani name since no link table support yet
            vont_name = item['name']
            pair_name = self.v_ont_anis[vont_name]['preferred-channel-pair'] \
                if vont_name in self.v_ont_anis else None

            if pair_name is not None:
                pon_ids = {val[pon_type] for val in self.channel_terminations.itervalues()
                           if val['channel-pair'] == pair_name}

        elif isinstance(data, VEnetConfig):
            venet_name = item['name']
            vont_name = self.v_enets[venet_name]['vont-ani'] \
                if venet_name in self.v_enets else None

            if vont_name is not None and vont_name in self.v_ont_anis:
                pair_name = self.v_ont_anis[vont_name]['preferred-channel-pair']
                pon_ids = {val[pon_type] for val in self.channel_terminations.itervalues()
                           if val['channel-pair'] == pair_name}

        elif isinstance(data, TcontsConfigData):
            tcont_name = item['name']
            vont_name = self.tconts[tcont_name]['vont-ani'] \
                if tcont_name in self.tconts else None

            if vont_name is not None and vont_name in self.v_ont_anis:
                pair_name = self.v_ont_anis[vont_name]['preferred-channel-pair']
                pon_ids = {val[pon_type] for val in self.channel_terminations.itervalues()
                           if val['channel-pair'] == pair_name}

        elif isinstance(data, TrafficDescriptorProfileData):
            td_name = item['name']

        elif isinstance(data, GemportsConfigData):
            gem_name = item['name']
            venet_name = self.gem_ports[gem_name]['venet-ref'] \
                if gem_name in self.gem_ports else None

            vont_name = self.v_enets[venet_name]['vont-ani'] \
                if venet_name in self.v_enets else None

            if vont_name is not None and vont_name in self.v_ont_anis:
                pair_name = self.v_ont_anis[vont_name]['preferred-channel-pair']
                pon_ids = {val[pon_type] for val in self.channel_terminations.itervalues()
                           if val['channel-pair'] == pair_name}

        elif isinstance(data, MulticastGemportsConfigData):
            raise NotImplementedError('TODO')

        elif isinstance(data, MulticastDistributionSetData):
            raise NotImplementedError('TODO')

        for pon_id in pon_ids:
            pon_port = self.southbound_ports.get(pon_id, None)
            if pon_port is not None:
                ports.append(pon_port)

        return ports

    def get_related_onus(self, item, pon_type='xgs-ponid'):
        onus = []
        pons = self.get_related_pons(item, pon_type=pon_type)
        data = item['data']

        for pon in pons:
            if isinstance(data, (OntaniConfig, VOntaniConfig)):
                # ont_ani name == vont_ani name since no link table support yet
                vont_name = item['name']
                for onu in pon.onus:
                    if onu.xpon_name == vont_name:
                        onus.append(onu)

            elif isinstance(data, VEnetConfig):
                venet_name = item['name']
                vont_name = self.v_enets[venet_name]['vont-ani'] \
                    if venet_name in self.v_enets else None

                if vont_name is not None and vont_name in self.v_ont_anis:
                    for onu in pon.onus:
                        if onu.xpon_name == vont_name:
                            onus.append(onu)

            elif isinstance(data, TcontsConfigData):
                tcont_name = item['name']
                vont_name = self.tconts[tcont_name]['vont-ani'] \
                    if tcont_name in self.tconts else None

                if vont_name is not None and vont_name in self.v_ont_anis:
                    for onu in pon.onus:
                        if onu.xpon_name == vont_name:
                            onus.append(onu)

            elif isinstance(data, TrafficDescriptorProfileData):
                pass

            elif isinstance(data, GemportsConfigData):
                gem_name = item['name']
                venet_name = self.gem_ports[gem_name]['venet-ref'] \
                    if gem_name in self.gem_ports else None

                vont_name = self.v_enets[venet_name]['vont-ani'] \
                    if venet_name in self.v_enets else None

                if vont_name is not None and vont_name in self.v_ont_anis:
                    for onu in pon.onus:
                        if onu.xpon_name == vont_name:
                            onus.append(onu)

            elif isinstance(data, MulticastGemportsConfigData):
                raise NotImplementedError('TODO')

            elif isinstance(data, MulticastDistributionSetData):
                raise NotImplementedError('TODO')

        return onus

    def _get_xpon_collection(self, data):
        collection, create, modify, delete = super(AdtranOltXPON, self)._get_xpon_collection(data)

        if collection is not None:
            return collection, create, modify, delete

        elif isinstance(data, ChannelgroupConfig):
            return self.channel_groups, \
                   self.on_channel_group_create,\
                   self.on_channel_group_modify, \
                   self.on_channel_group_delete

        elif isinstance(data, ChannelpartitionConfig):
            return self.channel_partitions,\
                   self.on_channel_partition_create,\
                   self.on_channel_partition_modify,\
                   self.on_channel_partition_delete

        elif isinstance(data, ChannelpairConfig):
            return self.channel_pairs, \
                   self.on_channel_pair_create,\
                   self.on_channel_pair_modify, \
                   self.on_channel_pair_delete

        elif isinstance(data, ChannelterminationConfig):
            return self.channel_terminations,\
                   self.on_channel_termination_create,\
                   self.on_channel_termination_modify,\
                   self.on_channel_termination_delete
        return None, None, None, None

    def _data_to_dict(self, data, td=None):
        result = super(AdtranOltXPON, self)._data_to_dict(data, td=td)

        if result is not None:
            return result

        name = data.name
        interface = data.interface
        inst_data = data.data

        if isinstance(data, ChannelgroupConfig):
            return 'channel-group', {
                'name': name,
                'enabled': interface.enabled,
                'system-id': inst_data.system_id,
                'polling-period': inst_data.polling_period,
                'data': data
            }

        elif isinstance(data, ChannelpartitionConfig):
            def _auth_method_enum_to_string(value):
                from voltha.protos.bbf_fiber_types_pb2 import SERIAL_NUMBER, LOID, \
                    REGISTRATION_ID, OMCI, DOT1X
                return {
                    SERIAL_NUMBER: 'serial-number',
                    LOID: 'loid',
                    REGISTRATION_ID: 'registration-id',
                    OMCI: 'omci',
                    DOT1X: 'dot1x'
                }.get(value, 'unknown')

            return 'channel-partition', {
                'name': name,
                'enabled': interface.enabled,
                'authentication-method': _auth_method_enum_to_string(inst_data.authentication_method),
                'channel-group': inst_data.channelgroup_ref,
                'fec-downstream': inst_data.fec_downstream,
                'mcast-aes': inst_data.multicast_aes_indicator,
                'differential-fiber-distance': inst_data.differential_fiber_distance,
                'data': data
            }

        elif isinstance(data, ChannelpairConfig):
            return 'channel-pair', {
                'name': name,
                'enabled': interface.enabled,
                'channel-group': inst_data.channelgroup_ref,
                'channel-partition': inst_data.channelpartition_ref,
                'line-rate': inst_data.channelpair_linerate,
                'data': data
            }

        elif isinstance(data, ChannelterminationConfig):
            return 'channel-termination', {
                'name': name,
                'enabled': interface.enabled,
                'xgs-ponid': inst_data.xgs_ponid,
                'xgpon-ponid': inst_data.xgpon_ponid,
                'channel-pair': inst_data.channelpair_ref,
                'ber-calc-period': inst_data.ber_calc_period,
                'data': data
            }

        else:
            raise NotImplementedError('Unknown data type')

    def on_channel_group_create(self, cgroup):
        return cgroup   # Implement in your OLT, if needed

    def on_channel_group_modify(self, cgroup, update, diffs):
        return update   # Implement in your OLT, if needed

    def on_channel_group_delete(self, cgroup):
        return None   # Implement in your OLT, if needed

    def on_channel_partition_create(self, cpartition):
        return cpartition   # Implement in your OLT, if needed

    def on_channel_partition_modify(self, cpartition, update, diffs):
        return update   # Implement in your OLT, if needed

    def on_channel_partition_delete(self, cpartition):
        return None   # Implement in your OLT, if needed

    def on_channel_pair_create(self, cpair):
        return cpair   # Implement in your OLT, if needed

    def on_channel_pair_modify(self, cpair, update, diffs):
        return update   # Implement in your OLT, if needed

    def on_channel_pair_delete(self, cpair):
        return None   # Implement in your OLT, if needed

    def on_channel_termination_create(self, cterm):
        return cterm   # Implement in your OLT, if needed

    def on_channel_termination_modify(self, cterm, update, diffs):
        return update   # Implement in your OLT, if needed

    def on_channel_termination_delete(self, cterm):
        return None   # Implement in your OLT, if needed
