# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import structlog
from enum import Enum
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message
from simplejson import dumps

from common.event_bus import EventBusClient
from voltha.core.config.config_proxy import CallbackType
from voltha.protos import third_party
from voltha.protos.events_pb2 import ConfigEvent, ConfigEventType

IGNORED_CALLBACKS = [CallbackType.PRE_ADD, CallbackType.GET,
                     CallbackType.POST_LISTCHANGE, CallbackType.PRE_REMOVE,
                     CallbackType.PRE_UPDATE]

log = structlog.get_logger()

class ConfigEventBus(object):

    __slots__ = (
        '_event_bus_client',  # The event bus client used to publish events.
        '_topic'  # the topic to publish to
    )

    def __init__(self):
        self._event_bus_client = EventBusClient()
        self._topic = 'model-change-events'

    def advertise(self, type, data, hash=None):
        if type in IGNORED_CALLBACKS:
            log.info('Ignoring event {} with data {}'.format(type, data))
            return

        if type is CallbackType.POST_ADD:
            kind = ConfigEventType.add
        elif type is CallbackType.POST_REMOVE:
            kind = ConfigEventType.remove
        else:
            kind = ConfigEventType.update

        if isinstance(data, Message):
            msg = dumps(MessageToDict(data, True, True))
        else:
            msg = data

        event = ConfigEvent(
            type=kind,
            hash=hash,
            data=msg
        )

        self._event_bus_client.publish(self._topic, event)

