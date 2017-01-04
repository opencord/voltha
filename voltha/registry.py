#!/usr/bin/env python
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
Simple component registry to provide centralized access to any registered
components.
"""
from collections import OrderedDict
from zope.interface import Interface


class IComponent(Interface):
    """
    A Voltha Component
    """

    def start():
        """
        Called once the componet is instantiated. Can be used for async
        initialization.
        :return: (None or Deferred)
        """

    def stop():
        """
        Called once before the component is unloaded. Can be used for async
        cleanup operations.
        :return: (None or Deferred)
        """


class Registry(object):

    def __init__(self):
        self.components = OrderedDict()

    def register(self, name, component):
        assert IComponent.providedBy(component)
        assert name not in self.components
        self.components[name] = component
        return component

    def unregister(self, name):
        if name in self.components:
            del self.components[name]

    def __call__(self, name):
        return self.components[name]

    def iterate(self):
        return self.components.values()


# public shared registry
registry = Registry()
