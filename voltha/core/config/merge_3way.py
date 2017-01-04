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
3-way merge function for config rev objects.
"""
from collections import OrderedDict
from copy import copy

from voltha.core.config.config_proxy import CallbackType, OperationContext
from voltha.core.config.config_rev import children_fields


class MergeConflictException(Exception):
    pass


def merge_3way(fork_rev, src_rev, dst_rev, merge_child_func, dry_run=False):
    """
    Attempt to merge src_rev into dst_rev but taking into account what have
    changed in both revs since the last known common point, the fork_rev.
    In case of conflict, raise a MergeConflictException(). If dry run is True,
    don't actually perform the merge, but detect potential conflicts.

    This function recurses into all children nodes stored under the rev and
    performs the merge if the children is also part of a transaction branch.

    :param fork_rev: Point of forking (last known common state between branches
    :param src_rev: Latest rev from which we merge to dst_rev
    :param dst_rev: Target (destination) rev
    :param merge_child_fun: To run a potential merge in all children that
    may need merge (determined from the local changes)
    :param dry_run: If True, do not perform the merge, but detect merge
    conflicts.
    :return: The new dst_rev (a new rev instance) the list of changes that
    occurred in this node or any of its children as part of this merge.
    """

    # to collect change tuples of (<callback-type>, <op-context>)
    changes = []

    class AnalyzeChanges(object):
        def __init__(self, lst1, lst2, keyname):
            self.keymap1 = OrderedDict((getattr(rev._config._data, keyname), i)
                                       for i, rev in enumerate(lst1))
            self.keymap2 = OrderedDict((getattr(rev._config._data, keyname), i)
                                       for i, rev in enumerate(lst2))
            self.added_keys = [
                k for k in self.keymap2.iterkeys() if k not in self.keymap1]
            self.removed_keys = [
                k for k in self.keymap1.iterkeys() if k not in self.keymap2]
            self.changed_keys = [
                k for k in self.keymap1.iterkeys()
                if k in self.keymap2 and
                    lst1[self.keymap1[k]]._hash != lst2[self.keymap2[k]]._hash
            ]

    # Note: there are a couple of special cases that can be optimized
    # for larer on. But since premature optimization is a bad idea, we
    # defer them.

    # deal with config data first
    if dst_rev._config is fork_rev._config:
        # no change in master, accept src if different
        config_changed = dst_rev._config != src_rev._config
    else:
        if dst_rev._config.hash != src_rev._config.hash:
            raise MergeConflictException('Config collision')
        config_changed = True

    # now to the external children fields
    new_children = dst_rev._children.copy()
    _children_fields = children_fields(fork_rev.data.__class__)

    for field_name, field in _children_fields.iteritems():

        fork_list = fork_rev._children[field_name]
        src_list = src_rev._children[field_name]
        dst_list = dst_rev._children[field_name]

        if dst_list == src_list:
            # we do not need to change the dst, however we still need
            # to complete the branch purging in child nodes so not
            # to leave dangling branches around
            [merge_child_func(rev) for rev in src_list]
            continue

        if not field.key:
            # If the list is not keyed, we really should not merge. We merely
            # check for collision, i.e., if both changed (and not same)
            if dst_list == fork_list:
                # dst branch did not change since fork

                assert src_list != fork_list, 'We should not be here otherwise'

                # the incoming (src) rev changed, and we have to apply it
                new_children[field_name] = [
                    merge_child_func(rev) for rev in src_list]

                if field.is_container:
                    changes.append((CallbackType.POST_LISTCHANGE,
                                    OperationContext(field_name=field_name)))

            else:
                if src_list != fork_list:
                    raise MergeConflictException(
                        'Cannot merge because single child node or un-keyed'
                        'children list has changed')

        else:

            if dst_list == fork_list:
                # Destination did not change

                # We need to analyze only the changes on the incoming rev
                # since fork
                src = AnalyzeChanges(fork_list, src_list, field.key)

                new_list = copy(src_list)  # we start from the source list

                for key in src.added_keys:
                    idx = src.keymap2[key]
                    new_rev = merge_child_func(new_list[idx])
                    new_list[idx] = new_rev
                    changes.append(
                        (CallbackType.POST_ADD,
                         new_rev.data))
                         # OperationContext(
                         #     field_name=field_name,
                         #     child_key=key,
                         #     data=new_rev.data)))

                for key in src.removed_keys:
                    old_rev = fork_list[src.keymap1[key]]
                    changes.append((
                        CallbackType.POST_REMOVE,
                        old_rev.data))
                        # OperationContext(
                        #     field_name=field_name,
                        #     child_key=key,
                        #     data=old_rev.data)))

                for key in src.changed_keys:
                    idx = src.keymap2[key]
                    new_rev = merge_child_func(new_list[idx])
                    new_list[idx] = new_rev
                    # updated child gets its own change event

                new_children[field_name] = new_list

            else:

                # For keyed fields we can really investigate what has been
                # added, removed, or changed in both branches and do a
                # fine-grained collision detection and merge

                src = AnalyzeChanges(fork_list, src_list, field.key)
                dst = AnalyzeChanges(fork_list, dst_list, field.key)

                new_list = copy(dst_list)  # this time we start with the dst

                for key in src.added_keys:
                    # we cannot add if it has been added and is different
                    if key in dst.added_keys:
                        # it has been added to both, we need to check if
                        # they are the same
                        child_dst_rev = dst_list[dst.keymap2[key]]
                        child_src_rev = src_list[src.keymap2[key]]
                        if child_dst_rev.hash == child_src_rev.hash:
                            # they match, so we do not need to change the
                            # dst list, but we still need to purge the src
                            # branch
                            merge_child_func(child_dst_rev)
                        else:
                            raise MergeConflictException(
                                'Cannot add because it has been added and '
                                'different'
                            )
                    else:
                        # this is a brand new key, need to add it
                        new_rev = merge_child_func(src_list[src.keymap2[key]])
                        new_list.append(new_rev)
                        changes.append((
                            CallbackType.POST_ADD,
                            new_rev.data))
                            # OperationContext(
                            #     field_name=field_name,
                            #     child_key=key,
                            #     data=new_rev.data)))

                for key in src.changed_keys:
                    # we cannot change if it was removed in dst
                    if key in dst.removed_keys:
                        raise MergeConflictException(
                            'Cannot change because it has been removed')

                    # if it changed in dst as well, we need to check if they
                    # match (same change
                    elif key in dst.changed_keys:
                        child_dst_rev = dst_list[dst.keymap2[key]]
                        child_src_rev = src_list[src.keymap2[key]]
                        if child_dst_rev.hash == child_src_rev.hash:
                            # they match, so we do not need to change the
                            # dst list, but we still need to purge the src
                            # branch
                            merge_child_func(child_src_rev)
                        elif child_dst_rev._config.hash != child_src_rev._config.hash:
                            raise MergeConflictException(
                                'Cannot update because it has been changed and '
                                'different'
                            )
                        else:
                            new_rev = merge_child_func(
                                src_list[src.keymap2[key]])
                            new_list[dst.keymap2[key]] = new_rev
                            # no announcement for child update

                    else:
                        # it only changed in src branch
                        new_rev = merge_child_func(src_list[src.keymap2[key]])
                        new_list[dst.keymap2[key]] = new_rev
                        # no announcement for child update

                for key in reversed(src.removed_keys):  # we go from highest
                                                        # index to lowest

                    # we cannot remove if it has changed in dst
                    if key in dst.changed_keys:
                        raise MergeConflictException(
                            'Cannot remove because it has changed')

                    # if it has not been removed yet from dst, then remove it
                    if key not in dst.removed_keys:
                        dst_idx = dst.keymap2[key]
                        old_rev = new_list.pop(dst_idx)
                        changes.append((
                            CallbackType.POST_REMOVE,
                            old_rev.data))
                            # OperationContext(
                            #     field_name=field_name,
                            #     child_key=key,
                            #     data=old_rev.data)))

                new_children[field_name] = new_list

    if not dry_run:
        rev = src_rev if config_changed else dst_rev
        rev = rev.update_all_children(new_children, dst_rev._branch)
        if config_changed:
            changes.append((CallbackType.POST_UPDATE, rev.data))
        return rev, changes

    else:
        return None, None
