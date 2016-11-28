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
import time

from structlog import get_logger
from twisted.internet import reactor, task
from voltha.adapters.microsemi.PAS5211 import PAS5211MsgGetProtocolVersion, PAS5211MsgGetOltVersion

log = get_logger()

class States(object):
    DISCONNECTED = 0
    FETCH_VERSION = 1
    CONNECTED = 2

class State(object):

    def __init__(self):
        pass

    """
    Attempt an operation towards the OLT
    """
    def run(self):
        raise NotImplementedError()

    """
    Dictates which state to transtion to.
    Predicated on the run operation to be successful.
    """
    def transition(self):
        raise NotImplementedError()

    """
    Returns the current state name
    """
    def state(self):
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
    Indicates whether to abandon trying to connect.
    """
    def abandon(self):
        raise  NotImplementedError()

"""
Represents an OLT in disconnected or pre init state.
"""
class Disconnected(State):

    def __init__(self, pas_comm, retry=3):
        self.comm = pas_comm
        self.completed = False
        self.packet = None
        self.retry = retry
        self.attempt = 1

    def run(self):
        self.packet = self.comm.communicate(PAS5211MsgGetProtocolVersion())
        if self.packet is not None:
            self.packet.show()
            self.completed = True
        else:
            if self.attempt <= self.retry:
                time.sleep(self.attempt)
                self.attempt += 1
        return self.completed

    def transition(self):
        if self.completed:
            return Fetch_Version(self.comm)
        else:
            return self

    def state(self):
        return States.DISCONNECTED

    def value(self):
        # TODO return a nicer value than the packet.
        return self.packet

    def send_msg(self, msg):
        raise NotImplementedError()

    def disconnect(self):
        pass

    def abandon(self):
        return self.attempt > self.retry

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
            self.packet.show()
            self.completed = True
        return self.completed

    def transition(self):
        if self.completed:
            return Connected(self.comm)
        else:
            return self

    def state(self):
        return States.FETCH_VERSION

    def value(self):
        # TODO return a nicer value than the packet.
        return self.packet

    def send_msg(self, msg):
        raise NotImplementedError()

    def disconnect(self):
        raise NotImplementedError()

    def abandon(self):
        return False


"""
OLT is in connected State
"""
class Connected(State):
    def __init__(self, pas_comm):
        self.comm = pas_comm
        self.completed = False
        self.packet = None
        self.scheduled = False
        self.scheduledTask = task.LoopingCall(self.keepalive)

    def run(self):
        if not self.scheduled:
            self.scheduled = True
            self.scheduledTask.start(1.0)

    def transition(self):
        if self.completed:
            return Disconnected(self.comm)
        else:
            return self

    def state(self):
        return States.CONNECTED

    def value(self):
        # TODO return a nicer value than the packet.
        return self.packet

    def send_msg(self, msg):
        return self.comm.communicate(msg)

    def keepalive(self):
        if self.completed:
            log.info('OLT has been disconnected')
            return
        self.packet = self.comm.communicate(PAS5211MsgGetOltVersion())
        if self.packet is None:
            self.completed = True
        else:
            self.packet.show()

    def disconnect(self):
        print "Disconnecting OLT"
        if self.scheduled:
            self.completed = True
            self.scheduledTask.stop()
        return self.transition()

    def abandon(self):
        return False