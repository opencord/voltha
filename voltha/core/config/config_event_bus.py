import structlog
from enum import Enum

from common.event_bus import EventBusClient
from voltha.core.config.config_proxy import CallbackType
from voltha.protos.events_pb2 import ConfigEvent

IGNORED_CALLBACKS = [CallbackType.PRE_ADD, CallbackType.GET,
                     CallbackType.POST_LISTCHANGE, CallbackType.PRE_REMOVE,
                     CallbackType.PRE_UPDATE]

log = structlog.get_logger()


class EventType(Enum):
    """
    Published events are after the fact meaning that only after
    something has happened do we advertise it. This eliminates
    eventually consistent-like behaviour where an external entity
    may think that an event has occured but actually the config
    store is still updating.
    """
    ADD = 0
    REMOVE = 1
    UPDATE = 2


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
            kind = EventType.ADD
        elif type is CallbackType.POST_REMOVE:
            kind = EventType.REMOVE
        else:
            kind = EventType.UPDATE

        event = ConfigEvent(
            type=kind,
            hash=hash,
            data=data
        )

        self._event_bus_client.publish(self._topic, event)

