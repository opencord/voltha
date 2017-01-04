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

""" Async sleep (asleep) method and other twisted goodies """

from twisted.internet import reactor
from twisted.internet.defer import Deferred


def asleep(dt):
    """
    Async (event driven) wait for given time period (in seconds)
    :param dt: Delay in seconds
    :return: Deferred to be fired with value None when time expires.
    """
    d = Deferred()
    reactor.callLater(dt, lambda: d.callback(None))
    return d
