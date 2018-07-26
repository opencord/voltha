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
A config rev object that persists itself
"""
from bz2 import compress, decompress

import structlog
from simplejson import dumps, loads

from voltha.core.config.config_rev import ConfigRevision, children_fields

log = structlog.get_logger()


class PersistedConfigRevision(ConfigRevision):

    compress = False

    __slots__ = ('_kv_store',)

    def __init__(self, branch, data, children=None):
        self._kv_store = branch._node._root._kv_store
        super(PersistedConfigRevision, self).__init__(branch, data, children)

    def _finalize(self):
        super(PersistedConfigRevision, self)._finalize()
        self.store()

    def __del__(self):
        try:
            if self._hash:
                if self._config.__weakref__ is None:
                    if self._config._hash in self._kv_store:
                        del self._kv_store[self._config._hash]
                assert self.__weakref__ is None
                if self._hash in self._kv_store:
                    del self._kv_store[self._hash]
        except Exception, e:
            # this should never happen
            log.exception('del-error', hash=self.hash, e=e)

    def store(self):

        try:
            # crude serialization of children hash and config data hash
            if self._hash in self._kv_store:
                return

            self.store_config()

            children_lists = {}
            for field_name, children in self._children.iteritems():
                hashes = [rev.hash for rev in children]
                children_lists[field_name] = hashes

            data = dict(
                children=children_lists,
                config=self._config._hash
            )
            blob = dumps(data)
            if self.compress:
                blob = compress(blob)

            self._kv_store[self._hash] = blob

        except Exception, e:
            log.exception('store-error', e=e)

    @classmethod
    def load(cls, branch, kv_store, msg_cls, hash):
        #  Update the branch's config store
        blob = kv_store[hash]
        if cls.compress:
            blob = decompress(blob)
        data = loads(blob)

        config_hash = data['config']
        config_data = cls.load_config(kv_store, msg_cls, config_hash)

        children_list = data['children']
        assembled_children = {}
        node = branch._node
        for field_name, meta in children_fields(msg_cls).iteritems():
            child_msg_cls = tmp_cls_loader(meta.module, meta.type)
            children = []
            for child_hash in children_list[field_name]:
                child_node = node._mknode(child_msg_cls)
                child_node.load_latest(child_hash)
                child_rev = child_node.latest
                children.append(child_rev)
            assembled_children[field_name] = children
        rev = cls(branch, config_data, assembled_children)
        return rev

    def store_config(self):
        if self._config._hash in self._kv_store:
            return

        # crude serialization of config data
        blob = self._config._data.SerializeToString()
        if self.compress:
            blob = compress(blob)

        self._kv_store[self._config._hash] = blob

    @classmethod
    def load_config(cls, kv_store, msg_cls, config_hash):
        blob = kv_store[config_hash]
        if cls.compress:
            blob = decompress(blob)

        # TODO use a loader later on
        data = msg_cls()
        data.ParseFromString(blob)
        return data


def tmp_cls_loader(module_name, cls_name):
    # TODO this shall be generalized
    from voltha.protos import voltha_pb2, health_pb2, adapter_pb2, \
        logical_device_pb2, device_pb2, openflow_13_pb2, bbf_fiber_base_pb2, \
        bbf_fiber_traffic_descriptor_profile_body_pb2, \
        bbf_fiber_tcont_body_pb2, bbf_fiber_gemport_body_pb2, \
        bbf_fiber_multicast_gemport_body_pb2, \
        bbf_fiber_multicast_distribution_set_body_pb2, \
        omci_mib_db_pb2, \
        omci_alarm_db_pb2
    return getattr(locals()[module_name], cls_name)
