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
Voltha internal diagnostics
"""

import arrow
import gc
import structlog
import resource

import sys
from simplejson import dumps
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from zope.interface import implementer

from common.event_bus import EventBusClient
from voltha.protos.events_pb2 import KpiEvent2, KpiEventType, MetricInformation, MetricMetaData
from voltha.registry import IComponent, registry

log = structlog.get_logger()


@implementer(IComponent)
class Diagnostics(object):

    def __init__(self, config):
        self.config = config
        self.periodic_check_interval = config.get(
            'periodic_check_interval', 15)
        self.periodic_checks = None
        self.event_bus = EventBusClient()
        self.instance_id = registry('main').get_args().instance_id

    def start(self):
        log.debug('starting')
        self.periodic_checks = LoopingCall(self.run_periodic_checks)
        self.periodic_checks.start(self.periodic_check_interval)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        if self.periodic_checks is not None:
            self.periodic_checks.stop()
        log.info('stopped')

    def run_periodic_checks(self):

        ts = arrow.utcnow().float_timestamp

        def deferreds():
            return len(gc.get_referrers(Deferred))

        def rss_mb():
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024
            if sys.platform.startswith('darwin'):
                rss /= 1024
            return rss

        kpi_event = KpiEvent2(
            type=KpiEventType.slice,
            ts=ts,
            slice_data=[
                MetricInformation(metadata=MetricMetaData(title='voltha.internal',
                                                          ts=ts,
                                                          context={'instance_id': self.instance_id}),
                                  metrics={'deferreds': deferreds(),
                                           'rss-mb': rss_mb()}
                                  )
                ])
        self.event_bus.publish('kpis', kpi_event)
        log.debug('periodic-check', ts=ts)

