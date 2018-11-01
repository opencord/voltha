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
from voltha.protos.bbf_fiber_tcont_body_pb2 import TcontsConfigData
from voltha.protos.bbf_fiber_traffic_descriptor_profile_body_pb2 import TrafficDescriptorProfileData
from voltha.protos.bbf_fiber_gemport_body_pb2 import GemportsConfigData

log = structlog.get_logger()


class AdtranXPON(object):
    """
    Class to abstract common OLT and ONU xPON operations
    """
    def __init__(self, **kwargs):
        # xPON config dictionaries
        self._v_ont_anis = {}             # Name -> dict
        self._ont_anis = {}               # Name -> dict
        self._tconts = {}                 # Name -> dict
        self._traffic_descriptors = {}    # Name -> dict
        self._gem_ports = {}              # Name -> dict

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
        :param data: xPON object          TODO: These three are still needed for the ONU until
                                                xPON is deprecated as the OLT calls into the ONU
                                                to start it up and passes these three ProtoBuf
                                                messages.
        """
        if isinstance(data, TcontsConfigData):
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

        return None, None, None, None

    def _data_to_dict(self, data, td=None):
        if isinstance(data, TcontsConfigData):
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
        return None

    def create_tcont(self, tcont_data, td_data):
        """
        Create TCONT information
        :param tcont_data:
        :param td_data:
        """
        log.debug('create-tcont', tcont=tcont_data, td=td_data)

        # Handle TD first, then TCONT
        if td_data is not None:
            try:
                self.xpon_create(td_data)

            except Exception as e:
                log.exception('td-create', td=td_data)

        try:
            td = self.traffic_descriptors.get(td_data.name) if td_data is not None else None
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
            from voltha.adapters.adtran_olt.adtran_olt_handler import OnuIndication
            if isinstance(data, OnuIndication):   # Ignore this
                return
            raise ValueError('Unknown data type: {}'.format(type(data)))

        item_type, new_item = self._data_to_dict(data, td=td)

        if name in items:
            # Treat like an update. It will update collection if needed
            return self.xpon_update(data, td=td)

        log.debug('new-item', item_type=item_type, item=new_item)
        items[name] = new_item

        if create_method is not None:
            try:
                new_item = create_method(new_item)
            except Exception as e:
                log.exception('xpon-create', item=new_item, e=e)

        if new_item is not None:
            items[name] = new_item
        else:
            del items[name]

    def xpon_update(self, data, td=None):
        log.debug('xpon-update', data=data)
        name = data.name
        items, create, update_method, delete = self._get_xpon_collection(data)

        if items is None:
            raise ValueError('Unknown data type: {}'.format(type(data)))

        existing_item = items.get(name)
        if existing_item is None:
            raise KeyError("'{}' not found. Type: {}".format(name, type(data)))

        item_type, update_item = self._data_to_dict(data, td=td)
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
        raise NotImplementedError("xPON support has been disabled")

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
