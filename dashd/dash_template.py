#!/usr/bin/env python
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

from structlog import get_logger
from twisted.internet.defer import DeferredList, inlineCallbacks
import requests
import sys
#
# This file contains the dashboard template information. It gets pulled into
# the dashd module and used to createt he dashboards. The other option would
# be to put each of these in an individual text file and read them in when the
# dashd process starts. There isn't much advantage to doing so at this time.
#
# TODO: The creation of a template from Grafana is currently incomplete.

log = get_logger()

class DashTemplate(object):
    def __init__(self, grafana_url):
        self.grafana_url = grafana_url

        self.rowSelector = '%port%' # Not currently used
        self.rows = [
            dict(
                title = "%port% packet statistics"
            )
        ]
        self.panels = [
            dict(
                title = "%port% Packet Receive Statistics",
                rx_64_pkts = \
                ("alias(perSecond(voltha.%device%.%deviceId%.%port%.rx_64_pkts), "
                 "'64b pkts/sec')"
                ),
                rx_65_127_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.rx_65_127_pkts), "
                 " '65-127b pkts/sec')"
                ),
                rx_128_255_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.rx_128_255_pkts), "
                 "'128-255b pkts/sec')"
                ),
                rx_256_511_pkts = \
                ("alias(perSecond"
                 "(voltha.%device%.%deviceId%.%port%.rx_256_511_pkts), "
                 "'256-511b pkts/sec')"
                ),
                rx_512_1023_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.rx_512_1023_pkts), "
                 "'512-1023b pkts/sec')"
                ),
                rx_1024_1518_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.rx_1024_1518_pkts), "
                 "'1024-1518b pkts/sec')"
                ),
                rx_1519_9k_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.rx_1519_9k_pkts), "
                 "'1519b-9kb pkts/sec')"
                )
            ),
            dict(
                title = "%port% Packet Send Statistics",
                tx_64_pkts = \
                ("alias(perSecond(voltha.%device%.%deviceId%.%port%.tx_64_pkts), "
                 "'64b pkts/sec')"
                ),
                tx_65_127_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.tx_65_127_pkts), "
                 "'65-127b pkts/sec')"
                ),
                tx_128_255_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.tx_128_255_pkts), "
                 "'128-255b pkts/sec')"
                ),
                tx_256_511_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.tx_256_511_pkts), "
                 "'256-511b pkts/sec')"
                ),
                tx_512_1023_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.tx_512_1023_pkts), "
                 "'512-1023b pkts/sec')"
                ),
                tx_1024_1518_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.tx_1024_1518_pkts), "
                 "'1024-1518b pkts/sec')"
                ),
                tx_1519_9k_pkts = \
                ("alias(perSecond("
                 "voltha.%device%.%deviceId%.%port%.tx_1519_9k_pkts), "
                 "'1519b-9kb pkts/sec')"
                )
            )
        ]


        self.dashRow = '''
        {
            "collapse": false,
            "editable": true,
            "height": "250px",
            "title": "Row",
            "panels": []
        }
        '''

        self.dashTarget = '''
        {
            "refId": "",
            "target": ""
        }
        '''

        self.dashPanel =  '''
        {
                  "aliasColors": {},
                  "bars": false,
                  "datasource": "Voltha Stats",
                  "editable": true,
                  "error": false,
                  "fill": 0,
                  "grid": {
                    "threshold1": null,
                    "threshold1Color": "rgba(216, 200, 27, 0.27)",
                    "threshold2": null,
                    "threshold2Color": "rgba(234, 112, 112, 0.22)"
                  },
                  "id": 1,
                  "isNew": true,
                  "legend": {
                    "avg": false,
                    "current": false,
                    "max": false,
                    "min": false,
                    "show": true,
                    "total": false,
                    "values": false
                  },
                  "lines": true,
                  "linewidth": 1,
                  "links": [],
                  "nullPointMode": "connected",
                  "percentage": false,
                  "pointradius": 5,
                  "points": false,
                  "renderer": "flot",
                  "seriesOverrides": [],
                  "span": 6,
                  "stack": false,
                  "steppedLine": false,
                  "targets": [
                  ],
                  "timeFrom": null,
                  "timeShift": null,
                  "title": "",
                  "tooltip": {
                    "msResolution": true,
                    "shared": true,
                    "value_type": "cumulative"
                  },
                  "type": "graph",
                  "xaxis": {
                    "show": true
                  },
                  "yaxes": [
                    {
                      "format": "short",
                      "label": null,
                      "logBase": 1,
                      "max": null,
                      "min": null,
                      "show": true
                    },
                    {
                      "format": "short",
                      "label": null,
                      "logBase": 1,
                      "max": null,
                      "min": null,
                      "show": true
                    }
                  ]
                }
        '''
        self.dashBoard = '''
        {
            "dashboard":{
              "annotations": {
                "list": []
              },
                  "refresh": "1m",
              "editable": true,
              "hideControls": false,
              "id": null,
              "overwrite": true,
              "links": [],
              "rows": [
              ],
              "schemaVersion": 12,
              "sharedCrosshair": false,
              "style": "dark",
              "tags": [],
              "templating": {
                "list": []
              },
              "time": {
                "from": "now-30m",
                "to": "now"
              },
              "timepicker": {
                "refresh_intervals": [
                  "5s",
                  "10s",
                  "30s",
                  "1m",
                  "5m",
                  "15m",
                  "30m",
                  "1h",
                  "2h",
                  "1d"
                ],
                "time_options": [
                  "5m",
                  "15m",
                  "1h",
                  "6h",
                  "12h",
                  "24h",
                  "2d",
                  "7d",
                  "30d"
                ]
              },
              "timezone": "browser",
              "title": "",
              "version": 0
            }
        }
        '''

    #TODO This functionality is a work in progress and needs to be completed.
    def apply_template(self, tplt_info):
        # The tplt_info is the record returned by Grafana as a result of a
        # search request. This includes the id, title, uri, and other fields
        # of no interest to us. The URI provides the key to access the
        # dashboard definition from which we'll create a template.
        try:
            r = requests.get(self.grafana_url + "/dashboards/" + \
                             tplt_info['uri'])
            db = r.json()
            # We don't need all the meta-data so just keep the dashboard
            # definition
            db = db['dashboard']
            # We need to null out the id to create new dashboards with the
            # template.
            db['id'] = None
            # Extract the rows and empty them from the template
            rows = db['rows']
            db['rows']=[]
            # Determine if the rows are wildcarded or fixed, if wildcarded they
            # need to map to the port which will create one row per port if
            # they're not wildcarded then the title will be used as the port id
            # and the same fixed number of rows will be used for every
            # dashboard.
            # Wildcarding implies a single row so check that first.
            if len(rows) == 1:
                # We might have wildcarding, search for it in the row titile
                match = re.search(r'%port%',rows[0]['title'])
                if match:
                    # Yes there is a wildcard, flag it
                    log.info("Wildcard found in template row") #debug
                else:
                    log.info("No wildcard found in template row") #debug
            else:
                # We don't have wildcarding
                log.info("No wildcard possible in multi-row template") #debug

        except:
            e = sys.exc_info()
            print("ERROR: ", e)
