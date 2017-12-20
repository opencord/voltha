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
from traffic_descriptor import TrafficDescriptor
from voltha.protos.bbf_fiber_base_pb2 import \
    OntaniConfig, VOntaniConfig, VEnetConfig
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData
from voltha.protos.bbf_fiber_multicast_gemport_body_pb2 import \
    MulticastGemportsConfigData
from voltha.protos.bbf_fiber_multicast_distribution_set_body_pb2 import \
    MulticastDistributionSetData

log = structlog.get_logger()


class AdtranXPON(object):
    """
    Class to abstract common OLT and ONU xPON operations
    """
    def __init__(self, **kwargs):
        # xPON config dictionaries
        self._v_ont_anis = {}             # Name -> dict
        self._ont_anis = {}               # Name -> dict
        self._v_enets = {}                # Name -> dict
        self._tconts = {}                 # Name -> dict
        self._traffic_descriptors = {}    # Name -> dict
        self._gem_ports = {}              # Name -> dict
        self._mcast_gem_ports = {}        # Name -> dict
        self._mcast_dist_sets = {}        # Name -> dict
        self._cached_xpon_pon_info = {}   # PON-id -> dict

    @property
    def v_ont_anis(self):
        return self._v_ont_anis

    @property
    def ont_anis(self):
        return self._ont_anis

    @property
    def v_enets(self):
        return self._v_enets

    @property
    def tconts(self):
        return self._tconts

    @property
    def traffic_descriptors(self):
        return self._traffic_descriptors

    @property
    def gem_ports(self):
        return self._gem_ports

    def _get_xpon_collection(self, data):
        """
        Get the collection for the object type and handler routines
        :param data: xPON object
        """
        if isinstance(data, OntaniConfig):
            return self.ont_anis, \
                   self.on_ont_ani_create,\
                   self.on_ont_ani_modify, \
                   self.on_ont_ani_delete

        elif isinstance(data, VOntaniConfig):
            return self.v_ont_anis, \
                   self.on_vont_ani_create,\
                   self.on_vont_ani_modify, \
                   self.on_vont_ani_delete

        elif isinstance(data, VEnetConfig):
            return self.v_enets, \
                   self.on_venet_create,\
                   self.on_venet_modify, \
                   self.on_venet_delete

        elif isinstance(data, TcontsConfigData):
            return self.tconts, \
                   self.on_tcont_create,\
                   self.on_tcont_modify, \
                   self.on_tcont_delete

        elif isinstance(data, TrafficDescriptorProfileData):
            return self.traffic_descriptors, \
                   self.on_td_create,\
                   self.on_td_modify, \
                   self.on_td_delete

        elif isinstance(data, GemportsConfigData):
            return self.gem_ports, \
                   self.on_gemport_create,\
                   self.on_gemport_modify, \
                   self.on_gemport_delete

        elif isinstance(data, MulticastGemportsConfigData):
            return self.mcast_gem_ports, \
                   self.on_mcast_gemport_create,\
                   self.on_mcast_gemport_modify, \
                   self.on_mcast_gemport_delete

        elif isinstance(data, MulticastDistributionSetData):
            return self.mcast_dist_sets, \
                   self.on_mcast_dist_set_create,\
                   self.on_mcast_dist_set_modify, \
                   self.on_mcast_dist_set_delete

        return None, None, None, None

    def _data_to_dict(self, data, td=None):
        if isinstance(data, OntaniConfig):
            name = data.name
            interface = data.interface
            inst_data = data.data

            return 'ont-ani', {
                'name': name,
                'description': interface.description,
                'enabled': interface.enabled,
                'upstream-fec': inst_data.upstream_fec_indicator,
                'mgnt-gemport-aes': inst_data.mgnt_gemport_aes_indicator,
                'data': data
            }
        elif isinstance(data, VOntaniConfig):
            name = data.name
            interface = data.interface
            inst_data = data.data

            return 'vOnt-ani', {
                'name': name,
                'description': interface.description,
                'enabled': interface.enabled,
                'onu-id': inst_data.onu_id,
                'expected-serial-number': inst_data.expected_serial_number,
                'preferred-channel-pair': inst_data.preferred_chanpair,
                'channel-partition': inst_data.parent_ref,
                'upstream-channel-speed': inst_data.upstream_channel_speed,
                'data': data
            }
        elif isinstance(data, VEnetConfig):
            name = data.name
            interface = data.interface
            inst_data = data.data

            return 'vEnet', {
                'name': name,
                'description': interface.description,
                'enabled': interface.enabled,
                'vont-ani': inst_data.v_ontani_ref,
                'data': data
            }
        elif isinstance(data, TcontsConfigData):
            return 'TCONT', {
                'name': data.name,
                'alloc-id': data.alloc_id,
                'vont-ani': data.interface_reference,
                'td-ref': td['name'],
                'data': data
            }
        elif isinstance(data, TrafficDescriptorProfileData):
            additional = TrafficDescriptor.AdditionalBwEligibility.from_value(
                data.additional_bw_eligibility_indicator)

            return 'Traffic-Desc', {
                'name': data.name,
                'fixed-bandwidth': data.fixed_bandwidth,
                'assured-bandwidth': data.assured_bandwidth,
                'maximum-bandwidth': data.maximum_bandwidth,
                'priority': data.priority,
                'weight': data.weight,
                'additional-bw-eligibility-indicator': additional,
                'data': data
            }
        elif isinstance(data, GemportsConfigData):
            return 'GEMPort', {
                'name': data.name,
                'gemport-id': data.gemport_id,
                'tcont-ref': data.tcont_ref,
                'encryption': data.aes_indicator,
                'traffic-class': data.traffic_class,
                'venet-ref': data.itf_ref,                # vENET
                'data': data
            }
        elif isinstance(data, MulticastGemportsConfigData):
            return 'MCAST-GEM', {
                'name': data.name,
                'gemport-id': data.gemport_id,
                'traffic-class': data.traffic_class,
                'is-broadcast': data.is_broadcast,
                'channel-pair-ref': data.itf_ref,                 # channel-pair
                'data': data
            }
        elif isinstance(data, MulticastDistributionSetData):
            data_dict = {
                'name': data.name,
                'multicast-gemport-ref': data.multicast_gemport_ref,
                'multicast-vlans-all': None,
                'multicast-vlans-list': [],
                'data': data
            }
            assert True is False, 'Need to decode multicast-vlans parameter'
            return 'MCAST-Distribution', data_dict

        return None

    def create_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Create TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        log.debug('create-tcont', tcont=tcont_data, td=traffic_descriptor_data)

        # Handle TD first, then TCONT
        try:
            self.xpon_create(traffic_descriptor_data)

        except Exception as e:
            log.exception('td-create', td=traffic_descriptor_data)

        try:
            td = self.traffic_descriptors.get(traffic_descriptor_data.name)
            self.xpon_create(tcont_data, td=td)

        except Exception as e:
            log.exception('tcont-create', tcont=tcont_data)

    def update_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Update TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        log.debug('update-tcont', tcont=tcont_data, td=traffic_descriptor_data)

        # Handle TD first, then TCONT. The TD may be new
        try:
            items, _, _, _ = self._get_xpon_collection(traffic_descriptor_data)
            existing_item = items.get(traffic_descriptor_data.name)
            if existing_item is None:
                self.xpon_create(traffic_descriptor_data)
            else:
                self.xpon_update(traffic_descriptor_data)

        except Exception as e:
            log.exception('td-update', td=traffic_descriptor_data)

        try:
            self.xpon_update(tcont_data)

        except Exception as e:
            log.exception('tcont-update', tcont=tcont_data)

    def remove_tcont(self, tcont_data, traffic_descriptor_data):
        """
        Remove TCONT information
        :param tcont_data:
        :param traffic_descriptor_data:
        """
        log.debug('remove-tcont', tcont=tcont_data, td=traffic_descriptor_data)

        # Handle TCONT first when removing, then TD
        try:
            self.xpon_remove(traffic_descriptor_data)
        except Exception as e:
            log.exception('td-update', td=traffic_descriptor_data)

        try:
            self.xpon_remove(tcont_data)
        except Exception as e:
            log.exception('tcont-update', tcont=tcont_data)

    def xpon_create(self, data, td=None):
        log.debug('xpon-create', data=data)

        name = data.name
        items, create_method, update_method, _ = self._get_xpon_collection(data)

        if items is None:
            raise ValueError('Unknown data type: {}'.format(type(data)))

        item_type, new_item = self._data_to_dict(data, td=td)

        if name in items:
            # Treat like an update. It will update collection if needed
            return self.xpon_update(data)

        log.debug('new-item', item_type=item_type, item=new_item)
        items[name] = new_item
        self._cached_xpon_pon_info = {}  # Clear cached data

        if create_method is not None:
            try:
                new_item = create_method(new_item)
            except Exception as e:
                log.exception('xpon-create', item=new_item, e=e)

        if new_item is not None:
            items[name] = new_item
        else:
            del items[name]

    def xpon_update(self, data):
        log.debug('xpon-update', data=data)

        name = data.name
        items, create, update_method, delete = self._get_xpon_collection(data)

        if items is None:
            raise ValueError('Unknown data type: {}'.format(type(data)))

        existing_item = items.get(name)
        if existing_item is None:
            raise KeyError("'{}' not found. Type: {}".format(name, type(data)))

        item_type, update_item = self._data_to_dict(data)
        log.debug('update-item', item_type=item_type, item=update_item)

        def _dict_diff(lhs, rhs):
            """
            Compare the values of two dictionaries and return the items in 'rhs'
            that are different than 'lhs. The RHS dictionary keys can be a subset of the
            LHS dictionary, or the RHS dictionary keys can contain new values.

            :param lhs: (dict) Original dictionary values
            :param rhs: (dict) New dictionary values to compare to the original (lhs) dict
            :return: (dict) Dictionary with differences from the RHS dictionary
            """
            lhs_keys = {k for k in lhs.keys() if k not in ['object', 'data']}
            rhs_keys = {k for k in rhs.keys() if k not in ['object', 'data']}
            assert len(lhs_keys) == len(lhs_keys & rhs_keys), 'Dictionary Keys do not match'
            return {k: v for k, v in rhs.items() if k not in lhs or lhs[k] != rhs[k]}

        # Calculate the difference
        diffs = _dict_diff(existing_item, update_item)

        if len(diffs) == 0:
            log.debug('update-item-no-diffs')
            return

        items[name] = update_item
        self._cached_xpon_pon_info = {}  # Clear cached data

        # Act on any changed items
        if update_method is not None:
            try:
                update_item = update_method(existing_item, update_item, diffs)
            except Exception as e:
                log.exception('xpon-update', existing=existing_item,
                              update=update_item, diffs=diffs,
                              e=e)

        if update_item is not None:
            items[name] = update_item
        else:
            del items[name]

    def xpon_remove(self, data):
        log.debug('xpon_remove', data=data)
        name = data.name

        items, create, update, delete_method = self._get_xpon_collection(data)
        item = items.get(name)

        if item is not None:
            if delete_method is None:
                item = None
            else:
                try:
                    item = delete_method(item)

                except Exception as e:
                    log.exception('xpon-remove', item=items, e=e)

            self._cached_xpon_pon_info = {}  # Clear cached data

            if item is None:
                del items[name]
            else:
                # Update item in collection (still referenced somewhere)
                items[name] = item

    def on_ont_ani_create(self, ont_ani):
        """
        A new ONT-ani is being created. You can override this method to
        perform custom operations as needed. If you override this method, you can add
        additional items to the item dictionary to track additional implementation
        key/value pairs.

        :param ont_ani: (dict) new ONT-ani
        :return: (dict) Updated ONT-ani dictionary, None if item should be deleted
        """
        return ont_ani   # Implement in your OLT, if needed

    def on_ont_ani_modify(self, ont_ani, update, diffs):
        """
        A existing ONT-ani is being updated. You can override this method to
        perform custom operations as needed. If you override this method, you can add
        additional items to the item dictionary to track additional implementation
        key/value pairs.

        :param ont_ani: (dict) existing ONT-ani item dictionary
        :param update: (dict) updated (changed) ONT-ani
        :param diffs: (dict) collection of items different in the update
        :return: (dict) Updated ONT-ani dictionary, None if item should be deleted
        """
        return update   # Implement in your OLT, if needed

    def on_ont_ani_delete(self, ont_ani):
        """
        A existing ONT-ani is being deleted. You can override this method to
        perform custom operations as needed. If you override this method, you can add
        additional items to the item dictionary to track additional implementation
        key/value pairs.

        :param ont_ani: (dict) ONT-ani to delete
        :return: (dict) None if item should be deleted
        """
        return None   # Implement in your OLT, if needed

    def on_vont_ani_create(self, vont_ani):
        return vont_ani   # Implement in your OLT, if needed

    def on_vont_ani_modify(self, vont_ani, update, diffs):
        return update   # Implement in your OLT, if needed

    def on_vont_ani_delete(self, vont_ani):
        return None   # Implement in your OLT, if needed

    def on_venet_create(self, venet):
        return venet   # Implement in your OLT, if needed

    def on_venet_modify(self, venet, update, diffs):
        return update   # Implement in your OLT, if needed

    def on_venet_delete(self, venet):
        return None   # Implement in your OLT, if needed

    def on_tcont_create(self, tcont):
        return tcont   # Implement in your OLT, if needed

    def on_tcont_modify(self, tcont, update, diffs):
        return update   # Implement in your OLT, if needed

    def on_tcont_delete(self, tcont):
        return None   # Implement in your OLT, if needed

    def on_td_create(self, traffic_desc):
        return traffic_desc   # Implement in your OLT, if needed

    def on_td_modify(self, traffic_desc, update, diffs):
        return update   # Implement in your OLT, if needed

    def on_td_delete(self, traffic_desc):
        return None   # Implement in your OLT, if needed

    def on_gemport_create(self, gem_port):
        return gem_port   # Implement in your OLT, if needed

    def on_gemport_modify(self, gem_port, update, diffs):
        return update   # Implement in your OLT, if needed

    def on_gemport_delete(self, gem_port):
        return None   # Implement in your OLT, if needed

    def on_mcast_gemport_create(self, mcast_gem_port):
        return mcast_gem_port  # Implement in your OLT, if needed

    def on_mcast_gemport_modify(self, mcast_gem_port, update, diffs):
        return update  # Implement in your OLT, if needed

    def on_mcast_gemport_delete(self, mcast_gem_port):
        return None  # Implement in your OLT, if needed

    def on_mcast_dist_set_create(self, dist_set):
        return dist_set  # Implement in your OLT, if needed

    def on_mcast_dist_set_modify(self, dist_set, update, diffs):
        return update  # Implement in your OLT, if needed

    def on_mcast_dist_set_delete(self, dist_set):
        return None  # Implement in your OLT, if needed
