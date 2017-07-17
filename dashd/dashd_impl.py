#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

# This is a very simple implementation of a dashboard creation service that
# listens to the Kafka bus on the voltha.kpis toic looking for performance
# monitoring metrics for olts. If a new olt appears on the bus the service will
# create a dashboard for it for both packet and byte stats creating one row per
# port/stream and in each row one panel for packet stats and one for byte
# stats.
#
# TODO: Capture all of the metadata for existing dashboards from Grafana. We're
# only capturing the device and device id from the title which is good enough
# for now.
# TODO: Leverage Grafana to act as a template builder simplifying the
# specification of a template without having to resort to a separate API for
# the dashd service. The basic premise is a dashboard with any name except
# voltha.template is created for any device. Once happy with the dashboard it's
# renamed voltha.template and this will automatically trigger the creation of a
# new template to use for all dashboards. All existing dashboards are
# immediately deleted and new ones are created using the template. The template
# is renamed voltha.template.active and can be deleted at this point. This has
# been started.

#
# Metadata format.
# The metadata for each device from which relevant metrics are recieved are
# stored in a dash_meta dictionary structure as follows.
#
# {<device_id1>: {
#     device:<device_type>,
#     slug:<grafana_slug>,
#     timer: <timer_val>
#     created: <creation_status>
#     ports: {
#       <port_id>:[
#            <metric1>,
#            <metric2>,
#            ...,
#            <metricN>
#       ]
#     }
#  },
#  ...
#  <device_idN>: {
#  }
# }
#

from structlog import get_logger
from argparse import ArgumentParser

from afkak.client import KafkaClient
from afkak.common import (
    KafkaUnavailableError,
    OFFSET_LATEST)
from afkak.consumer import Consumer
from twisted.internet import reactor
from twisted.internet.defer import DeferredList, inlineCallbacks
from twisted.python.failure import Failure
from twisted.internet.task import LoopingCall

from common.utils.consulhelpers import get_endpoint_from_consul
import requests
import json
import re
import sys
import time
from dashd.dash_template import DashTemplate

log = get_logger()


class DashDaemon(object):
    def __init__(self, consul_endpoint, kafka_endpoint, grafana_url, topic="voltha.heartbeat"):
        #logging.basicConfig(
        # format='%(asctime)s:%(name)s:' +
        #        '%(levelname)s:%(process)d:%(message)s',
        # level=logging.INFO
        #)
        self.dash_meta = {}
        self.timer_resolution = 10
        self.timer_duration = 600
        self.topic = topic
        self.dash_template = DashTemplate(grafana_url)
        self.grafana_url = grafana_url
        self.kafka_endpoint = kafka_endpoint
        self.consul_endpoint = consul_endpoint

        if kafka_endpoint.startswith('@'):
            retrys = 10
            while True:
                try:
                    self.kafka_endpoint = get_endpoint_from_consul(
                        self.consul_endpoint, kafka_endpoint[1:])
                    break
                except:
                    log.error("unable-to-communicate-with-consul")
                    self.stop()
                retrys -= 1
                if retrys == 0:
                    log.error("unable-to-communicate-with-consul")
                    self.stop()
                time.sleep(10)

        self.on_start_callback = None

        self._client = KafkaClient(self.kafka_endpoint)
        self._consumer_list = []  # List of consumers
        # List of deferred returned from consumers' start() methods
        self._consumer_d_list = []

    def set_on_start_callback(self, on_start_callback):
        # This function is currently unused, future requirements.
        self.on_start_callback = on_start_callback
        return self

    @inlineCallbacks
    def start(self):
        partitions = []
        try:
            while not partitions:
                yield self._client.load_metadata_for_topics(self.topic)
                #self._client.load_metadata_for_topics(self.topic)
                e = self._client.metadata_error_for_topic(self.topic)
                if e:
                    log.warning('no-metadata-for-topic', error=e,
                                topic=self.topic)
                else:
                    partitions = self._client.topic_partitions[self.topic]
                    break
                time.sleep(20)
        except KafkaUnavailableError:
            log.error("unable-to-communicate-with-Kafka-brokers")
            self.stop()

        def _note_consumer_stopped(result, consumer):
            log.info('consumer-stopped', consumer=consumer,
                     result=result)

        for partition in partitions:
            c = Consumer(self._client, self.topic, partition,
                         self.msg_processor)
            self._consumer_list.append(c)
            log.info('consumer-started', topic=self.topic, partition=partition)
            d = c.start(OFFSET_LATEST)
            d.addBoth(_note_consumer_stopped, c)
            self._consumer_d_list.append(d)

        # Now read the list of existing dashboards from Grafana and create the
        # dictionary of dashboard timers. If we've crashed there will be
        # dashboards there. Just add them and if they're no longer valid
        # they'll be deleted. If they are valid then they'll persist.
        #print("Starting main loop")
        try:
            retrys = 10
            while True:
                r = requests.get(self.grafana_url + "/datasources")
                if r.status_code == requests.codes.ok:
                    break
                else:
                    retrys -= 1
                    if retrys == 0:
                        log.error("unable-to-communicate-with-grafana")
                        self.stop()
                    time.sleep(10)
            j = r.json()
            data_source = False
            for i in j:
                if i["name"] == "Voltha Stats":
                     data_source = True
                     break
            if not data_source:
                r = requests.post(self.grafana_url + "/datasources",
                data = {"name":"Voltha Stats","type":"graphite",
                        "access":"proxy","url":"http://localhost:81"})
                log.info('data-source-added',status=r.status_code, text=r.text)

            retrys = 10
            while True:
                r = requests.get(self.grafana_url + "/search?")
                if r.status_code == requests.codes.ok:
                    break
                else:
                    retrys -= 1
                    if retrys == 0:
                        log.error("unable-to-communicate-with-grafana")
                        self.stop()
                    time.sleep(10)
            j = r.json()
            for i in j:
                # Look for dashboards that have a title of *olt.[[:hexidgit:]].
                # These will be the ones of interest. Others should just be left
                # alone.
                #print(i['title'])
                match = re.search(r'(.*olt)\.([0-9a-zA-Z]+)',i['title'])
                if match and match.lastindex > 0:
                    #print(match.group(1), match.group(2))
                    self.dash_meta[match.group(2)] = {}
                    self.dash_meta[match.group(2)]['timer'] = self.timer_duration # 10 min
                    self.dash_meta[match.group(2)]['device'] = match.group(1)
                    self.dash_meta[match.group(2)]['created'] = False
                    self.dash_meta[match.group(2)]['ports'] = {}
                    # TODO: We should really capture all of the chart data
                    # including the rows, panels, and data points being logged.
                    # This is good enough for now though to determine if
                    # there's already a dashboard for a given device.


            def countdown_processor():
                # Called every X (timer_resolution) seconds to count down each of the
                # dash timers. If a timer reaches 0 the corresponding
                # dashboard is removed.
                #log.info("Counting down.")
                try:
                    for dashboard in self.dash_meta.keys():
                        #print("Counting down %s." %dashboard)
                        # Issue a log if the counter decrement is somewhat relevant
                        if(self.dash_meta[dashboard]['timer'] % 100 == 0 and \
                           self.dash_meta[dashboard]['timer'] != self.timer_duration):
                            log.info("counting-down",dashboard=dashboard,
                                     timer=self.dash_meta[dashboard]['timer'])
                        self.dash_meta[dashboard]['timer'] -= self.timer_resolution
                        if self.dash_meta[dashboard]['timer'] <= 0:
                            # Delete the dashboard here
                            log.info("FIXME:-Should-delete-the-dashboard-here",
                                     dashboard=dashboard)
                            pass
                except:
                    e = sys.exc_info()
                    log.error("error", error=e)
            # Start the dashboard countdown processor
            log.info("starting-countdown-processor")
            lc = LoopingCall(countdown_processor)
            lc.start(self.timer_resolution)

            @inlineCallbacks
            def template_checker():
                try:
                    # Called every so often (timer_resolution seconds because it's
                    # convenient) to check if a template dashboard has been defined
                    # in Grafana. If it has been, replace the built in template
                    # with the one provided
                    r = requests.get(self.grafana_url + "/search?query=template")
                    db = r.json()
                    if len(db) == 1:
                        # Apply the template
                        yield self.dash_template.apply_template(db[0])
                    elif len(db) != 0:
                        # This is an error, log it.
                        log.warning("More-than-one-template-provided-ignoring")
                except:
                    e = sys.exc_info()
                    log.error("error", error=e)

            log.info("starting-template-checker")
            lc = LoopingCall(template_checker)
            lc.start(self.timer_resolution)

        except:
            e = sys.exc_info()
            log.error("error", error=e)

    def stop(self):
        log.info("\n")
        log.info('end-of-execution-stopping-consumers')
        # Ask each of our consumers to stop. When a consumer fully stops, it
        # fires the deferred returned from its start() method. We saved all
        # those deferreds away (above, in start()) in self._consumer_d_list,
        # so now we'll use a DeferredList to wait for all of them...
        for consumer in self._consumer_list:
            consumer.stop()
        dl = DeferredList(self._consumer_d_list)

        # Once the consumers are all stopped, then close our client
        def _stop_client(result):
            if isinstance(result, Failure):
                log.error('error', result=result)
            else:
                log.info('all-consumers-stopped', client=self._client)
            self._client.close()
            return result

        dl.addBoth(_stop_client)

        # And once the client is shutdown, stop the reactor
        def _stop_reactor(result):
            reactor.stop()
            return result

        dl.addBoth(_stop_reactor)

    def check_for_dashboard(self, msg):
        need_dash = {}
        done = {}
        # Extract the ids for all olt(s) in the message and do one of 2
        # things. If it exists, reset the meta_data timer for the dashboard and
        # if it doesn't exist add it to the array of needed dashboards.
        metrics = json.loads(getattr(msg.message,'value'))['prefixes']
        for key in metrics.keys():
            match = re.search(r'voltha\.(.*olt)\.([0-9a-zA-Z]+)\.(.*)',key)
            if match and match.lastindex > 1:
                if match.group(2) in self.dash_meta and match.group(2) not in done:
                    # Update the delete countdown timer
                    self.dash_meta[match.group(2)]['timer'] = self.timer_duration
                    done[match.group(2)] = True
                    # Issue a log if the reset if somewhat relevant.
                    if self.dash_meta[match.group(2)]['timer'] < \
                    self.timer_duration - self.timer_resolution:
                        log.info("reset-timer",device=match.group(2))
                    #print("reset timer for: %s" %match.group(2))
                else:
                    # No dahsboard exists,
                    need_dash[key] = metrics[key]
        return need_dash

    def create_dashboards(self, createList):
        dataIds = "ABCDEFGHIJKLMNOP"
        for dash in createList:
            #log.info("creating a dashboard for: %s" % self.dash_meta[dash])
            # Create one row per "interface"
            # Create one panel per metric type for the time being it's one
            # panel for byte stats and one panel for packet stats.
            newDash = json.loads(self.dash_template.dashBoard)
            newDash['dashboard']['title'] = self.dash_meta[dash]['device'] + \
                    '.' + dash
            # The port is the main grouping attribute
            for port in self.dash_meta[dash]['ports']:
                # Add in the rows for the port specified by the template
                for row in self.dash_template.rows:
                    r = json.loads(self.dash_template.dashRow)
                    r['title'] = re.sub(r'%port%',port, row['title'])
                    p = {}
                    # Add the panels to the row per the template
                    panelId = 1
                    for panel in self.dash_template.panels:
                        p = json.loads(self.dash_template.dashPanel)
                        p['id'] = panelId
                        panelId += 1
                        p['title'] = re.sub(r'%port%', port.upper(), panel['title'])
                        t = {}
                        dataId = 0
                        # Add the targets to the panel
                        for dpoint in sorted(self.dash_meta[dash]['ports'][port]):
                            if dpoint in panel:
                                t['refId'] = dataIds[dataId]
                                db = re.sub(r'%port%',port,panel[dpoint])
                                db = re.sub(r'%device%',
                                            self.dash_meta[dash]['device'],db)
                                db = re.sub(r'%deviceId%', dash,db)
                                t['target'] = db
                                p['targets'].append(t.copy())
                                dataId += 1
                        r['panels'].append(p.copy())
                    newDash['dashboard']['rows'].append(r.copy())
            #print("NEW DASHBOARD: ",json.dumps(newDash))
            #print(r.json())
            r = \
            requests.post(self.grafana_url + "/dashboards/db",
                          json=newDash)
            self.dash_meta[dash]['slug'] = r.json()['slug']
            self.dash_meta[dash]['created'] = True
            log.info("created-dashboard", slug=self.dash_meta[dash]['slug'])

    def msg_processor(self, consumer, msglist):
        try:
            createList = []
            for msg in msglist:
                # Reset the timer for existing dashboards and get back a dict
                # of of dashboards to create if any.
                need_dash = self.check_for_dashboard(msg)
                # Now populate the meta data for all missing dashboards
                for key in need_dash.keys():
                    match = re.search(r'voltha\.(.*olt)\.([0-9a-zA-Z]+)\.(.*)',key)
                    if match and match.lastindex > 2:
                        if match.group(2) in self.dash_meta:
                            # The entry will have been created when the first
                            # port in the record was encountered so just
                            # populate the metrics and port info.
                            # TODO: The keys below are the names of the metrics
                            # that are in the Kafka record. This auto-discovery
                            # is fine if all that's needed are raw metrics. If
                            # metrics are "cooked" by a downstream process and
                            # subsequently fed to graphite/carbon without being
                            # re-posted to Kafka, discovery becomes impossible.
                            # In those cases and in cases where finer grain
                            # control of what's displayed is required, a config
                            # file would be necessary.
                            self.dash_meta[match.group(2)]['ports'][match.group(3)] = \
                            need_dash[key]['metrics'].keys()
                        else:
                            # Not there, create a meta-data record for the
                            # device and add this port.
                            #print("Adding meta data for", match.group(1),
                            #      match.group(2))
                            createList.append(match.group(2))
                            self.dash_meta[match.group(2)] = {}
                            self.dash_meta[match.group(2)]['timer'] = 600
                            self.dash_meta[match.group(2)]['device'] = match.group(1)
                            self.dash_meta[match.group(2)]['created'] = False
                            self.dash_meta[match.group(2)]['ports'] = {}
                            #print("Adding port", match.group(3), "to", match.group(1),
                            #      match.group(2))
                            self.dash_meta[match.group(2)]['ports'][match.group(3)] = \
                            need_dash[key]['metrics'].keys()
            # Now go ahead and create the dashboards using the meta data that
            # wwas just populated for them.
            if len(createList) != 0: # Create any missing dashboards.
                   self.create_dashboards(createList)
        except:
            e = sys.exc_info()
            log.error("error", error=e)

def parse_options():
    parser = ArgumentParser("Manage Grafana Dashboards")
    parser.add_argument("-c", "--consul",
                        help="consul ip and port",
                        default='10.100.198.220:8500')

    parser.add_argument("-t", "--topic",
                        help="topic to listen from",
                        default="voltha.kpis")

    parser.add_argument("-g", "--grafana_url",
                        help="graphana api url",
                        default= "http://admin:admin@localhost:8882/api")

    parser.add_argument("-k", "--kafka",
                        help="kafka bus",
                        default=None)

    parser.add_argument("-s", "--host",
                        help="docker host ip",
                        default=None)

    return parser.parse_args()

def main():
    logging.basicConfig(
        format='%(asctime)s:%(name)s:' +
               '%(levelname)s:%(process)d:%(message)s',
        level=logging.INFO
    )

    args = parse_options()

    dashd = DashDaemon(args.consul, args.kafka, args.grafana_url, args.topic)
    reactor.callWhenRunning(dashd.start)
    reactor.run()
    log.info("completed!")


if __name__ == "__main__":
    main()
