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
Base OLT State machine class
"""
import threading
import time
from voltha.adapters.microsemi.PAS5211 import PAS5211MsgGetProtocolVersion, PAS5211MsgGetOltVersion

class State(object):
    def __init__(self):
        pass

    """
    Attempt an operation towards the OLT
    """
    def run(self):
        raise NotImplementedError()

    """
    Distates which state to transtion to.
    Predicated on the run operation to be successful.
    """
    def transition(self):
        raise NotImplementedError()

    """
    Returns any useful information for the given State
    """
    def value(self):
        raise NotImplementedError()

    """
    Sends a message to this olt
    """
    def send_msg(self, msg):
        raise NotImplementedError()

    """
    Disconnected an OLT.
    """
    def disconnect(self):
        raise NotImplementedError()

"""
Represents an OLT in disconnected or pre init state.
"""
class Disconnected(State):

    def __init__(self, pas_comm):
        self.comm = pas_comm
        self.completed = False
        self.packet = None

    def run(self):
        self.packet = self.comm.communicate(PAS5211MsgGetProtocolVersion())
        if self.packet is not None:
            self.completed = True
        return self.completed

    def transition(self):
        if self.completed:
            return Fetch_Version(self.comm)

    def value(self):
        # TODO return a nicer value than the packet.
        return self.packet

    def send_msg(self, msg):
        raise NotImplementedError()

    def disconnect(self):
        raise NotImplementedError()

"""
Fetches the OLT version
"""
class Fetch_Version(State):
    def __init__(self, pas_comm):
        self.comm = pas_comm
        self.completed = False
        self.packet = None

    def run(self):
        self.packet = self.comm.communicate(PAS5211MsgGetOltVersion())
        if self.packet is not None:
            self.completed = True
        return self.completed

    def transition(self):
        if self.completed:
            return Connected(self.comm)

    def value(self):
        # TODO return a nicer value than the packet.
        return self.packet

    def send_msg(self, msg):
        raise NotImplementedError()

    def disconnect(self):
        raise NotImplementedError()


"""
OLT is in connected State
"""
class Connected(State):
    def __init__(self, pas_comm):
        self.comm = pas_comm
        self.completed = False
        self.packet = None
        self.t = threading.Thread(target = self.keepalive)

    def run(self):
        self.t.start()

    def transition(self):
        if self.completed:
            return Disconnected(self.comm)

    def value(self):
        # TODO return a nicer value than the packet.
        return self.packet

    def send_msg(self, msg):
        return self.comm.communicate(msg)

    # FIXME replace with twisted
    def keepalive(self):
        while not self.completed:
            self.packet = self.comm.communicate(PAS5211MsgGetOltVersion())
            if self.packet is not None:
                time.sleep(1)
            else:
                break
        self.completed = True

    def disconnect(self):
        print "Stopping"
        self.completed = True
