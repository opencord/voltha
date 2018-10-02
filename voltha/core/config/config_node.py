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
from copy import copy

from jsonpatch import JsonPatch
from jsonpatch import make_patch

from common.utils.json_format import MessageToDict
from voltha.core.config.config_branch import ConfigBranch
from voltha.core.config.config_event_bus import ConfigEventBus
from voltha.core.config.config_proxy import CallbackType, ConfigProxy
from voltha.core.config.config_rev import is_proto_message, children_fields, \
    ConfigRevision, access_rights
from voltha.core.config.config_rev_persisted import PersistedConfigRevision
from voltha.core.config.merge_3way import merge_3way
from voltha.protos import third_party
from voltha.protos import meta_pb2

import structlog

log = structlog.get_logger()

def message_to_dict(m):
    return MessageToDict(m, True, True, False)


def check_access_violation(new_msg, old_msg):
    """Raise ValueError if attempt is made to change a read-only field"""
    access_map = access_rights(new_msg.__class__)
    violated_fields = []
    for field_name, access in access_map.iteritems():
        if access == meta_pb2.READ_ONLY:
            if getattr(new_msg, field_name) != getattr(old_msg, field_name):
                violated_fields.append(field_name)
    if violated_fields:
        raise ValueError('Cannot change read-only field(s) %s' %
                         ', '.join('"%s"' % f for f in violated_fields))


def find_rev_by_key(revs, keyname, value):
    for i, rev in enumerate(revs):
        if getattr(rev._config._data, keyname) == value:
            return i, rev
    raise KeyError('key {}={} not found'.format(keyname, value))


class ConfigNode(object):
    """
    Represents a configuration node which can hold a number of revisions
    of the configuration for this node.
    When the configuration changes, the new version is appended to the
    node.
    Initial data must be a protobuf message and it will determine the type of
    this node.
    """
    __slots__ = (
        '_root',  # ref to root node
        '_type',  # node type, as __class__ of protobuf message
        '_branches',  # dict of transaction branches and a default (committed)
                      # branch
        '_tags',  # dict of tag-name to ref of ConfigRevision
        '_proxy',  # ref to proxy observer or None if no proxy assigned
        '_event_bus',  # ref to event_bus or None if no event bus is assigned
        '_auto_prune'
    )

    def __init__(self, root, initial_data, auto_prune=True, txid=None):
        self._root = root
        self._branches = {}
        self._tags = {}
        self._proxy = None
        self._event_bus = None
        self._auto_prune = auto_prune

        if isinstance(initial_data, type):
            self._type = initial_data
        elif is_proto_message(initial_data):
            self._type = initial_data.__class__
            copied_data = initial_data.__class__()
            copied_data.CopyFrom(initial_data)
            self._initialize(copied_data, txid)
        else:
            raise NotImplementedError()

    def _mknode(self, *args, **kw):
        return ConfigNode(self._root, *args, **kw)

    def _mkrev(self, *args, **kw):
        return self._root.mkrev(*args, **kw)

    def _initialize(self, data, txid):
        # separate external children data away from locally stored data
        # based on child_node annotations in protobuf
        children = {}
        for field_name, field in children_fields(self._type).iteritems():
            field_value = getattr(data, field_name)
            if field.is_container:
                if field.key:
                    keys_seen = set()
                    children[field_name] = lst = []
                    for v in field_value:
                        rev = self._mknode(v, txid=txid).latest
                        key = getattr(v, field.key)
                        if key in keys_seen:
                            raise ValueError('Duplicate key "{}"'.format(key))
                        lst.append(rev)
                        keys_seen.add(key)
                else:
                    children[field_name] = [
                        self._mknode(v, txid=txid).latest for v in field_value]
            else:
                children[field_name] = [
                    self._mknode(field_value, txid=txid).latest]
            data.ClearField(field_name)

        branch = ConfigBranch(self, auto_prune=self._auto_prune)
        rev = self._mkrev(branch, data, children)
        self._make_latest(branch, rev)
        self._branches[txid] = branch

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ accessors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # these convenience short-cuts only work for the committed branch

    @property
    def revisions(self):
        return [r._hash for r in self._branches[None]._revs.itervalues()]

    @property
    def latest(self):
        return self._branches[None]._latest

    def __getitem__(self, hash):
        return self._branches[None]._revs[hash]

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ get operation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def get(self, path=None, hash=None, depth=0, deep=False, txid=None):

        # depth preparation
        if deep:
            depth = -1

        # path preparation
        path = '' if path is None else path
        while path.startswith('/'):
            path = path[1:]

        # determine branch; if lookup fails, it is ok to use default branch
        branch = self._branches.get(txid, None) or self._branches[None]

        # determine rev
        if hash is not None:
            rev = branch._revs[hash]
        else:
            rev = branch.latest

        return self._get(rev, path, depth)

    def _get(self, rev, path, depth):

        if not path:
            return self._do_get(rev, depth)

        # ... otherwise
        name, _, path = path.partition('/')
        field = children_fields(self._type)[name]
        if field.is_container:
            if field.key:
                children = rev._children[name]
                if path:
                    # need to escalate further
                    key, _, path = path.partition('/')
                    key = field.key_from_str(key)
                    _, child_rev = find_rev_by_key(children, field.key, key)
                    child_node = child_rev.node
                    return child_node._get(child_rev, path, depth)
                else:
                    # we are the node of interest
                    response = []
                    for child_rev in children:
                        child_node = child_rev.node
                        value = child_node._do_get(child_rev, depth)
                        response.append(value)
                    return response
            else:
                if path:
                    raise LookupError(
                        'Cannot index into container with no key defined')
                response = []
                for child_rev in rev._children[name]:
                    child_node = child_rev.node
                    value = child_node._do_get(child_rev, depth)
                    response.append(value)
                return response
        else:
            child_rev = rev._children[name][0]
            child_node = child_rev.node
            return child_node._get(child_rev, path, depth)

    def _do_get(self, rev, depth):
        msg = rev.get(depth)
        if self._proxy is not None:
            msg = self._proxy.invoke_callbacks(CallbackType.GET, msg)
        return msg

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~ update operation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def update(self, path, data, strict=False, txid=None, mk_branch=None):

        while path.startswith('/'):
            path = path[1:]

        try:
            branch = self._branches[txid]
        except KeyError:
            branch = mk_branch(self)

        if not path:
            return self._do_update(branch, data, strict)

        rev = branch._latest  # change is always made to the latest
        name, _, path = path.partition('/')
        field = children_fields(self._type)[name]
        if field.is_container:
            if not path:
                raise ValueError('Cannot update a list')
            if field.key:
                key, _, path = path.partition('/')
                key = field.key_from_str(key)
                children = copy(rev._children[name])
                idx, child_rev = find_rev_by_key(children, field.key, key)
                child_node = child_rev.node
                # chek if deep copy will work better
                new_child_rev = child_node.update(
                    path, data, strict, txid, mk_branch)
                if new_child_rev.hash == child_rev.hash:
                    # When the new_child_rev goes out of scope,
                    # it's destructor gets invoked as it is not being
                    # referred by any other data structures.  To prevent
                    # this to trigger the hash it is holding from being
                    # erased in the db, its hash is set to None.  If the
                    # new_child_rev object is pointing at the same address
                    # as the child_rev address then do not clear the hash
                    if new_child_rev != child_rev:
                        log.debug('clear-hash',
                             hash=new_child_rev.hash, object_ref=new_child_rev)
                        new_child_rev.clear_hash()
                    return branch._latest
                if getattr(new_child_rev.data, field.key) != key:
                    raise ValueError('Cannot change key field')
                children[idx] = new_child_rev
                rev = rev.update_children(name, children, branch)
                self._make_latest(branch, rev)
                return rev
            else:
                raise ValueError('Cannot index into container with no keys')

        else:
            child_rev = rev._children[name][0]
            child_node = child_rev.node
            new_child_rev = child_node.update(
                path, data, strict, txid, mk_branch)
            rev = rev.update_children(name, [new_child_rev], branch)
            self._make_latest(branch, rev)
            return rev

    def _do_update(self, branch, data, strict):
        if not isinstance(data, self._type):
            raise ValueError(
                '"{}" is not a valid data type for this node'.format(
                    data.__class__.__name__))
        self._test_no_children(data)
        if self._proxy is not None:
            self._proxy.invoke_callbacks(CallbackType.PRE_UPDATE, data)

        if branch._latest.data != data:
            if strict:
                # check if attempt is made to change read-only field
                check_access_violation(data, branch._latest.data)
            rev = branch._latest.update_data(data, branch)
            self._make_latest(branch, rev,
                              ((CallbackType.POST_UPDATE, rev.data),))
            return rev
        else:
            return branch._latest

    def _make_latest(self, branch, rev, change_announcements=()):
        # Update the latest branch only when the hash between the previous
        # data and the new rev is different, otherwise this will trigger the
        # data already saved in the db (with that hash) to be erased
        if rev.hash not in branch._revs:
            branch._revs[rev.hash] = rev

        if not branch._latest or rev.hash != branch._latest.hash:
            branch._latest = rev

        # announce only if this is main branch
        if change_announcements and branch._txid is None:

            if self._proxy is not None:
                for change_type, data in change_announcements:
                    # since the callback may operate on the config tree,
                    # we have to defer the execution of the callbacks till
                    # the change is propagated to the root, then root will
                    # call the callbacks
                    self._root.enqueue_callback(
                        self._proxy.invoke_callbacks,
                        change_type,
                        data,
                        proceed_on_errors=1,
                    )

            for change_type, data in change_announcements:
                self._root.enqueue_notification_callback(
                    self._mk_event_bus().advertise,
                    change_type,
                    data,
                    hash=rev.hash
                )

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ add operation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def add(self, path, data, txid=None, mk_branch=None):
        while path.startswith('/'):
            path = path[1:]
        if not path:
            raise ValueError('Cannot add to non-container node')

        try:
            branch = self._branches[txid]
        except KeyError:
            branch = mk_branch(self)

        rev = branch._latest  # change is always made to latest
        name, _, path = path.partition('/')
        field = children_fields(self._type)[name]
        if field.is_container:
            if not path:
                # we do need to add a new child to the field
                if field.key:
                    if self._proxy is not None:
                        self._proxy.invoke_callbacks(
                            CallbackType.PRE_ADD, data)
                    children = copy(rev._children[name])
                    key = getattr(data, field.key)
                    try:
                        find_rev_by_key(children, field.key, key)
                    except KeyError:
                        pass
                    else:
                        raise ValueError('Duplicate key "{}"'.format(key))
                    child_rev = self._mknode(data).latest
                    children.append(child_rev)
                    rev = rev.update_children(name, children, branch)
                    self._make_latest(branch, rev,
                                      ((CallbackType.POST_ADD, data),))
                    return rev
                else:
                    # adding to non-keyed containers not implemented yet
                    raise ValueError('Cannot add to non-keyed container')
            else:
                if field.key:
                    # need to escalate
                    key, _, path = path.partition('/')
                    key = field.key_from_str(key)
                    children = copy(rev._children[name])
                    idx, child_rev = find_rev_by_key(children, field.key, key)
                    child_node = child_rev.node
                    new_child_rev = child_node.add(path, data, txid, mk_branch)
                    children[idx] = new_child_rev
                    rev = rev.update_children(name, children, branch)
                    self._make_latest(branch, rev)
                    return rev
                else:
                    raise ValueError(
                        'Cannot index into container with no keys')
        else:
            raise ValueError('Cannot add to non-container field')

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~ remove operation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def remove(self, path, txid=None, mk_branch=None):
        while path.startswith('/'):
            path = path[1:]
        if not path:
            raise ValueError('Cannot remove from non-container node')

        try:
            branch = self._branches[txid]
        except KeyError:
            branch = mk_branch(self)

        rev = branch._latest  # change is always made to latest
        name, _, path = path.partition('/')
        field = children_fields(self._type)[name]
        if field.is_container:
            if not path:
                raise ValueError("Cannot remove without a key")
            if field.key:
                key, _, path = path.partition('/')
                key = field.key_from_str(key)
                if path:
                    # need to escalate
                    children = copy(rev._children[name])
                    idx, child_rev = find_rev_by_key(children, field.key, key)
                    child_node = child_rev.node
                    new_child_rev = child_node.remove(path, txid, mk_branch)
                    children[idx] = new_child_rev
                    rev = rev.update_children(name, children, branch)
                    self._make_latest(branch, rev)
                    return rev
                else:
                    # need to remove from this very node
                    children = copy(rev._children[name])
                    idx, child_rev = find_rev_by_key(children, field.key, key)
                    if self._proxy is not None:
                        data = child_rev.data
                        self._proxy.invoke_callbacks(
                            CallbackType.PRE_REMOVE, data)
                        post_anno = ((CallbackType.POST_REMOVE, data),)
                    else:
                        post_anno = ((CallbackType.POST_REMOVE, child_rev.data),)
                    del children[idx]
                    rev = rev.update_children(name, children, branch)
                    self._make_latest(branch, rev, post_anno)
                    return rev
            else:
                raise ValueError('Cannot remove from non-keyed container')
        else:
            raise ValueError('Cannot remove non-conatiner field')

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Branching ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def _mk_txbranch(self, txid):
        branch_point = self._branches[None].latest
        branch = ConfigBranch(self, txid, branch_point)
        self._branches[txid] = branch
        return branch

    def _del_txbranch(self, txid):
        del self._branches[txid]

    def _merge_txbranch(self, txid, dry_run=False):
        """
        Make latest in branch to be latest in the common branch, but only
        if no conflict is detected. Conflict is where the txbranch branch
        point no longer matches the latest in the default branch. This has
        to be verified recursively.
        """

        def merge_child(child_rev):
            child_branch = child_rev._branch
            if child_branch._txid == txid:
                child_rev = child_branch._node._merge_txbranch(txid, dry_run)
            return child_rev

        src_branch = self._branches[txid]
        dst_branch = self._branches[None]

        fork_rev = src_branch.origin  # rev from which src branch was made
        src_rev = src_branch.latest  # head rev of source branch
        dst_rev = dst_branch.latest  # head rev of target branch

        rev, changes = merge_3way(
            fork_rev, src_rev, dst_rev, merge_child, dry_run)

        if not dry_run:
            self._make_latest(dst_branch, rev, change_announcements=changes)
            del self._branches[txid]

        return rev

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Diff utility ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def diff(self, hash1, hash2=None, txid=None):
        branch = self._branches[txid]
        rev1 = branch[hash1]
        rev2 = branch[hash2] if hash2 else branch._latest
        if rev1.hash == rev2.hash:
            return JsonPatch([])
        else:
            dict1 = message_to_dict(rev1.data)
            dict2 = message_to_dict(rev2.data)
            return make_patch(dict1, dict2)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~ Tagging utility ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def tag(self, tag, hash=None):
        branch = self._branches[None]  # tag only what has been committed
        rev = branch._latest if hash is None else branch._revs[hash]
        self._tags[tag] = rev
        self.persist_tags()
        return self

    @property
    def tags(self):
        return sorted(self._tags.iterkeys())

    def by_tag(self, tag):
        """
        Return revision based on tag
        :param tag: previously registered tag value
        :return: revision object
        """
        return self._tags[tag]

    def diff_by_tag(self, tag1, tag2):
        return self.diff(self._tags[tag1].hash, self._tags[tag2].hash)

    def delete_tag(self, tag):
        del self._tags[tag]
        self.persist_tags()

    def delete_tags(self, *tags):
        for tag in tags:
            del self._tags[tag]
        self.persist_tags()

    def prune_untagged(self):
        branch = self._branches[None]
        keep = set(rev.hash for rev in self._tags.itervalues())
        keep.add(branch._latest.hash)
        for hash in branch._revs.keys():
            if hash not in keep:
                del branch._revs[hash]
        return self

    def persist_tags(self):
        """
        Persist tag information to the backend
        """

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Internals ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def _test_no_children(self, data):
        for field_name, field in children_fields(self._type).items():
            field_value = getattr(data, field_name)
            if field.is_container:
                if len(field_value):
                    raise NotImplementedError(
                        'Cannot update external children')
            else:
                if data.HasField(field_name):
                    raise NotImplementedError(
                        'Cannot update externel children')

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~ Node proxy ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def get_proxy(self, path, exclusive=False):
        return self._get_proxy(path, self, path, exclusive)

    def _get_proxy(self, path, root, full_path, exclusive):
        while path.startswith('/'):
            path = path[1:]
        if not path:
            return self._mk_proxy(root, full_path, exclusive)

        # need to escalate
        rev = self._branches[None]._latest
        name, _, path = path.partition('/')
        field = children_fields(self._type)[name]
        if field.is_container:
            if not path:
                raise ValueError('Cannot proxy a container field')
            if field.key:
                key, _, path = path.partition('/')
                key = field.key_from_str(key)
                children = rev._children[name]
                _, child_rev = find_rev_by_key(children, field.key, key)
                child_node = child_rev.node
                return child_node._get_proxy(path, root, full_path, exclusive)

            raise ValueError('Cannot index into container with no keys')

        else:
            child_rev = rev._children[name][0]
            child_node = child_rev.node
            return child_node._get_proxy(path, root, full_path, exclusive)

    def _mk_proxy(self, root, full_path, exclusive):
        if self._proxy is None:
            self._proxy = ConfigProxy(root, self, full_path, exclusive)
        else:
            if self._proxy.exclusive:
                raise ValueError('Node is already owned exclusively')
        return self._proxy

    def _mk_event_bus(self):
        if self._event_bus is None:
            self._event_bus = ConfigEventBus()
        return self._event_bus

    # ~~~~~~~~~~~~~~~~~~~~~~~~ Persistence loading ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def load_latest(self, latest_hash):

        root = self._root
        kv_store = root._kv_store

        branch = ConfigBranch(node=self, auto_prune=self._auto_prune)
        rev = PersistedConfigRevision.load(
            branch, kv_store, self._type, latest_hash)
        self._make_latest(branch, rev)
        self._branches[None] = branch
