#
# Copyright 2018 the original author or authors.
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
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message
from simplejson import dumps
from common.event_bus import EventBusClient
from voltha.protos.omci_mib_db_pb2 import OpenOmciEvent
from voltha.protos.omci_alarm_db_pb2 import AlarmOpenOmciEvent
from common.utils.json_format import MessageToDict


class OpenOmciEventBus(object):
    """ Event bus for publishing OpenOMCI related events. """
    __slots__ = (
        '_event_bus_client',  # The event bus client used to publish events.
        '_topic'              # the topic to publish to
    )

    def __init__(self):
        self._event_bus_client = EventBusClient()
        self._topic = 'openomci-events'

    def message_to_dict(m):
        return MessageToDict(m, True, True, False)

    def advertise(self, event_type, data):
        if isinstance(data, Message):
            msg = dumps(MessageToDict(data, True, True))
        elif isinstance(data, dict):
            msg = dumps(data)
        else:
            msg = str(data)

        event_func = AlarmOpenOmciEvent if 'AlarmSynchronizer' in msg \
                                  else OpenOmciEvent
        event = event_func(
                type=event_type,
                data=msg
        )

        self._event_bus_client.publish(self._topic, event)
