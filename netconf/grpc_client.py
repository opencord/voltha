#
# Copyright 2016 the original author or authors.
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
The gRPC client layer for the Netconf agent
"""
from Queue import Queue, Empty
from structlog import get_logger
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredQueue


log = get_logger()


class GrpcClient(object):

    def __init__(self, connection_manager, channel):

        self.connection_manager = connection_manager
        self.channel = channel
        self.logical_stub = None

        self.stopped = False

        self.packet_out_queue = Queue()  # queue to send out PacketOut msgs
        self.packet_in_queue = DeferredQueue()  # queue to receive PacketIn

