# Copyright 2017-present Open Networking Foundation
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

import structlog
from twisted.internet.task import LoopingCall


class AdapterPmMetrics(object):
    """
    Base class for Device Adapter PM Metrics Manager

    Device specific (OLT, ONU, OpenOMCI, ...) will derive groups of PM information
    and this base class is primarily used to provide a consistent interface to configure,
    start, and stop statistics collection.
    """
    def __init__(self, adapter_agent, device_id,
                 grouped=False, freq_override=False, **kwargs):
        """
        Initializer for shared Device Adapter PM metrics manager

        :param adapter_agent: (AdapterAgent) Adapter agent for the device
        :param device_id: (str) Device ID
        :param grouped: (bool) Flag indicating if statistics are managed as a group
        :param freq_override: (bool) Flag indicating if frequency collection can be specified
                                     on a per group basis
        :param kwargs: (dict) Device Adapter specific values
        """
        self.log = structlog.get_logger(device_id=device_id)
        self.device_id = device_id
        self.adapter_agent = adapter_agent
        self.name = adapter_agent.adapter_name
        self.default_freq = 150
        self.grouped = grouped
        self.freq_override = grouped and freq_override
        self.lc = None
        self.prefix = 'voltha.{}.{}'.format(self.name, self.device_id)
        self.pm_group_metrics = dict()      # name -> PmGroupConfig

    def update(self, pm_config):
        # TODO: Move any common steps into base class
        raise NotImplementedError('Your derived class should override this method')

    def make_proto(self, pm_config=None):
        raise NotImplementedError('Your derived class should override this method')

    def start_collector(self, callback=None):
        """
        Start the collection loop for an adapter if the frequency > 0

        :param callback: (callable) Function to call to collect PM data
        """
        self.log.info("starting-pm-collection", device_name=self.name)
        if callback is None:
            callback = self.collect_and_publish_metrics

        if self.lc is None:
            self.lc = LoopingCall(callback)

        if self.default_freq > 0:
            self.lc.start(interval=self.default_freq / 10)

    def stop_collector(self):
        """ Stop the collection loop"""
        if self.lc is not None and self.default_freq > 0:
            self.lc.stop()

    def collect_group_metrics(self, group, names, config):
        """
        Collect the metrics for a specific PM group.

        This common collection method expects that the group object provide as the first
        parameter supports an attribute or property with the name of the value to
        retrieve.

        :param group: (object) The object to query for the value of various attributes (PM names)
        :param names: (set) A collection of PM names that, if implemented as a property in the object,
                            will return a value to store in the returned PM dictionary
        :param config: (PMConfig) PM Configuration settings. The enabled flag is examined to determine
                                  if the data associated with a PM Name will be collected.

        :return: (dict) collected metrics
        """
        metrics = dict()

        for (metric, t) in names:
            if config[metric].enabled and hasattr(group, metric):
                metrics[metric] = getattr(group, metric)

        return metrics

    def collect_metrics(self, metrics=None):
        """
        Collect metrics for this adapter.

        This method is called for each adapter at a fixed frequency. The adapter type
        (OLT, ONU, ..) should provide a derived class where this method iterates
        through all metrics and collects them up in a dictionary with the group/metric
        name as the key, and the metric values as the contents.

        For a group, the values are a map where   metric_name -> metric_value
        For and individual metric, the values are the metric value

        TODO: Currently all group metrics are collected on a single timer tick. This needs to be fixed.

        :param metrics: (dict) Existing map to add collected metrics to.  This is
                               provided to allow derived classes to call into further
                               encapsulated classes

        :return: (dict) metrics - see description above
        """
        raise NotImplementedError('Your derived class should override this method')

    def collect_and_publish_metrics(self):
        """ Request collection of all enabled metrics and publish them """
        try:
            metrics = self.collect_metrics()
            self.publish_metrics(metrics)

        except Exception as e:
            self.log.exception('failed-to-collect-kpis', e=e)

    def publish_metrics(self, metrics):
        """
        Publish the metrics during a collection

        :param metrics: (dict) Metrics to publish. If empty, no metrics will be published
        """
        self.log.debug('publish-metrics', metrics=metrics)

        if len(metrics):
            import arrow
            from voltha.protos.events_pb2 import KpiEvent, KpiEventType, MetricValuePairs

            try:
                ts = arrow.utcnow().timestamp
                kpi_event = KpiEvent(
                    type=KpiEventType.slice,
                    ts=ts,
                    prefixes={
                        self.prefix + '.{}'.format(k): MetricValuePairs(metrics=metrics[k])
                        for k in metrics.keys()}
                )
                self.adapter_agent.submit_kpis(kpi_event)

            except Exception as e:
                self.log.exception('failed-to-submit-kpis', e=e)

    # TODO: Need to support on-demand counter update if provided by the PM 'group'.
    #       Currently we expect PM data to be periodically polled by a separate
    #       mechanism. The on-demand counter update should be optional in case the
    #       particular device adapter group of data is polled anyway for other reasons.
