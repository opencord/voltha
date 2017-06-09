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
Immutable classes to store config revision information arranged in a tree.

Immutability cannot be enforced in Python, so anyoen working with these
classes directly must obey the rules.
"""

import weakref
from copy import copy
from hashlib import md5

from google.protobuf.descriptor import Descriptor
from simplejson import dumps

from common.utils.json_format import MessageToJson
from voltha.protos import third_party
from voltha.protos import meta_pb2

import structlog

log = structlog.get_logger()

def is_proto_message(o):
    """
    Return True if object o appears to be a protobuf message; False otherwise.
    """
    # use a somewhat empirical approach to decide if something looks like
    # a protobuf message
    return isinstance(getattr(o, 'DESCRIPTOR', None), Descriptor)


def message_to_json_concise(m):
    """
    Return the most concise string representation of a protobuf. Good for
    things where size matters (e.g., generating hash).
    """
    return MessageToJson(m, False, True, False)


_rev_cache = weakref.WeakValueDictionary()  # cache of config revs


_children_fields_cache = {}  # to memoize externally stored field name info


class _ChildType(object):
    """Used to store key metadata about child_node fields in protobuf messages.
    """
    __slots__ = (
        '_module',
        '_type',
        '_is_container',
        '_key',
        '_key_from_str'
    )

    def __init__(self, module, type, is_container,
                 key=None, key_from_str=None):
        self._module = module
        self._type = type
        self._is_container = is_container
        self._key = key
        self._key_from_str = key_from_str

    @property
    def is_container(self):
        return self._is_container

    @property
    def key(self):
        return self._key

    @property
    def key_from_str(self):
        return self._key_from_str

    @property
    def module(self):
        return self._module

    @property
    def type(self):
        return self._type


def children_fields(cls):
    """
    Return a map of externally stored fields for this protobuf message type.
    What is stored as branch node is determined by the "child_node"
    annotation in the protobuf definitions.
    With each external field, we store if the field is a container, if a
    container is keyed (indexed), and what is the function that converts
    path substring back to the key.
    """
    names = _children_fields_cache.get(cls)

    if names is None:
        names = {}

        for field in cls.DESCRIPTOR.fields:

            if field.has_options:
                options = field.GetOptions()

                if options.HasExtension(meta_pb2.child_node):
                    is_container = field.label == 3
                    meta = options.Extensions[meta_pb2.child_node]
                    key_from_str = None

                    if meta.key:
                        key_field = field.message_type.fields_by_name[meta.key]
                        key_type = key_field.type

                        if key_type == key_field.TYPE_STRING:
                            key_from_str = lambda s: s

                        elif key_type in (
                                key_field.TYPE_FIXED32,
                                key_field.TYPE_FIXED64,
                                key_field.TYPE_INT32,
                                key_field.TYPE_INT64,
                                key_field.TYPE_SFIXED32,
                                key_field.TYPE_SFIXED64,
                                key_field.TYPE_SINT32,
                                key_field.TYPE_SINT64,
                                key_field.TYPE_UINT32,
                                key_field.TYPE_UINT64):
                            key_from_str = lambda s: int(s)

                        else:
                            raise NotImplementedError()

                    field_class = field.message_type._concrete_class
                    names[field.name] = _ChildType(
                        module=field_class.__module__,
                        type=field_class.__name__,
                        is_container=is_container,
                        key=meta.key,
                        key_from_str=key_from_str
                    )

        _children_fields_cache[cls] = names

    return names


_access_right_cache = {}  # to memoize field access right restrictions


def access_rights(cls):
    """
    Determine the access rights for each field and cache these maps for
    fast retrieval.
    """
    access_map = _access_right_cache.get(cls)
    if access_map is None:
        access_map = {}
        for field in cls.DESCRIPTOR.fields:
            if field.has_options:
                options = field.GetOptions()
                if options.HasExtension(meta_pb2.access):
                    access = options.Extensions[meta_pb2.access]
                    access_map[field.name] = access
        _access_right_cache[cls] = access_map
    return access_map


class ConfigDataRevision(object):
    """
    Holds a specific snapshot of the local configuration for config node.
    It shall be treated as an immutable object, although in Python this is
    very difficult to enforce!
    As such, we can compute a unique hash based on the config data which
    can be used to establish equivalence. It also has a time-stamp to track
    changes.

    This object must be treated as immutable, including its nested config data.
    This is very important. The entire config module depends on hashes
    we create over the data, so altering the data can lead to unpredictable
    detriments.
    """

    __slots__ = (
        '_data',
        '_hash',
        '__weakref__'
    )

    def __init__(self, data):
        self._data = data
        self._hash = self._hash_data(data)

    @property
    def data(self):
        return self._data

    @property
    def hash(self):
        return self._hash

    @staticmethod
    def _hash_data(data):
        """Hash function to be used to track version changes of config nodes"""
        if isinstance(data, (dict, list)):
            to_hash = dumps(data, sort_keys=True)
        elif is_proto_message(data):
            to_hash = ':'.join((
                data.__class__.__module__,
                data.__class__.__name__,
                data.SerializeToString()))
        else:
            to_hash = str(hash(data))
        return md5(to_hash).hexdigest()[:12]


class ConfigRevision(object):
    """
    Holds not only the local config data, but also the external children
    reference lists, per field name.
    Recall that externally stored fields are those marked "child_node" in
    the protobuf definition.
    This object must be treated as immutable, including its config data.
    """

    __slots__ = (
        '_config',
        '_children',
        '_hash',
        '_branch',
        '__weakref__'
    )

    def __init__(self, branch, data, children=None):
        self._branch = branch
        self._config = ConfigDataRevision(data)
        self._children = children
        self._finalize()

    def _finalize(self):
        self._hash = self._hash_content()
        if self._hash not in _rev_cache:
            _rev_cache[self._hash] = self
        if self._config._hash not in _rev_cache:
            _rev_cache[self._config._hash] = self._config
        else:
            self._config = _rev_cache[self._config._hash]  # re-use!

    def _hash_content(self):
        # hash is derived from config hash and hashes of all children
        m = md5('' if self._config is None else self._config._hash)
        if self._children is not None:
            for child_field in sorted(self._children.keys()):
                children = self._children[child_field]
                assert isinstance(children, list)
                m.update(''.join(c._hash for c in children))
        return m.hexdigest()[:12]

    @property
    def hash(self):
        return self._hash

    @property
    def data(self):
        return None if self._config is None else self._config.data

    @property
    def node(self):
        return self._branch._node

    @property
    def type(self):
        return self._config.data.__class__

    def clear_hash(self):
        self._hash = None

    def get(self, depth):
        """
        Get config data of node. If depth > 0, recursively assemble the
        branch nodes. If depth is < 0, this results in a fully exhaustive
        "complete config".
        """
        orig_data = self._config.data
        data = orig_data.__class__()
        data.CopyFrom(orig_data)
        if depth:
            # collect children
            cfields = children_fields(self.type).iteritems()
            for field_name, field in cfields:
                if field.is_container:
                    for rev in self._children[field_name]:
                        child_data = rev.get(depth=depth - 1)
                        child_data_holder = getattr(data, field_name).add()
                        child_data_holder.MergeFrom(child_data)
                else:
                    rev = self._children[field_name][0]
                    child_data = rev.get(depth=depth - 1)
                    child_data_holder = getattr(data, field_name)
                    child_data_holder.MergeFrom(child_data)
        return data

    def update_data(self, data, branch):
        """Return a NEW revision which is updated for the modified data"""
        new_rev = copy(self)
        new_rev._branch = branch
        new_rev._config = self._config.__class__(data)
        new_rev._finalize()
        return new_rev

    def update_children(self, name, children, branch):
        """Return a NEW revision which is updated for the modified children"""
        new_children = self._children.copy()
        new_children[name] = children
        new_rev = copy(self)
        new_rev._branch = branch
        new_rev._children = new_children
        new_rev._finalize()
        return new_rev

    def update_all_children(self, children, branch):
        """Return a NEW revision which is updated for all children entries"""
        new_rev = copy(self)
        new_rev._branch = branch
        new_rev._children = children
        new_rev._finalize()
        return new_rev
