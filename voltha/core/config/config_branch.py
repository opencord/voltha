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
Class to hold revisions, latest revision, etc., for a config node, used
for the active committed revisions or revisions part of a transaction.
"""

from collections import OrderedDict
from weakref import WeakValueDictionary


class ConfigBranch(object):

    __slots__ = (
        '_node',  # ref to node
        '_txid',  # txid for this branch (None for the committed branch)
        '_origin',  # _latest at time of branching on default branch
        '_revs',  # dict of rev-hash to ref of ConfigRevision
        '_latest',  # ref to latest committed ConfigRevision
        '__weakref__'
    )

    def __init__(self, node, txid=None, origin=None, auto_prune=True):
        self._node = node
        self._txid = txid
        self._origin = origin
        self._revs = WeakValueDictionary() if auto_prune else OrderedDict()
        self._latest = origin

    def __getitem__(self, hash):
        return self._revs[hash]

    @property
    def latest(self):
        return self._latest

    @property
    def origin(self):
        return self._origin
