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

"""
Alarm-generator is a process that sends a stream of simulate_alarm requrests to VOLTHA. It will automatically pick
between a variety of ONU-related alarms. The number of alarms per second is configurable (for example, 0.01 = one
alarm per hundred seconds), and the duration of the alarm from RAISE to CLEAR is also configurable.

By default, if not device is specified, then VOLTHA will be queried for the first device.

Example:
    # Generate 1 request per second, each request a duration of 2 seconds. Use whatever OLT device id exists in
    # VOLTHA. Use intf_id =1234 and onu_device_id=5678
    main.py -C consul:8500 -g voltha:50555 -G -r 1 -u 2 -i 1234 -o 5678

    # Generate 1 request per second, each request a duration of 2 seconds. Use whatever OLT and ONUs exist in
    # VOLTHA.
    main.py -C consul:8500 -g voltha:50555 -G -r 1 -u 2

"""
import argparse
import copy
import functools
import os
import random
import structlog
import sys
import time
from threading import Timer

import grpc
from consul import Consul
from simplejson import dumps

from google.protobuf.empty_pb2 import Empty
from voltha.protos import third_party
from voltha.protos import voltha_pb2, voltha_pb2_grpc, common_pb2

defs = dict(
    # config=os.environ.get('CONFIG', './cli.yml'),
    consul=os.environ.get('CONSUL', 'localhost:8500'),
    voltha_grpc_endpoint=os.environ.get('VOLTHA_GRPC_ENDPOINT',
                                        'localhost:50055'),
    global_request=os.environ.get('GLOBAL_REQUEST', False),
    device_id = None,
    intf_id = "1234",
    onu_id = None,
    rate = 0.1,
    duration = 1,
)

def enum2name(msg_obj, enum_type, enum_value):
    descriptor = msg_obj.DESCRIPTOR.enum_types_by_name[enum_type]
    name = descriptor.values_by_number[enum_value].name
    return name

banner = """\
         _ _   _          
__ _____| | |_| |_  __ _   
\ V / _ \ |  _| ' \/ _` | Alarm Generator
 \_/\___/_|\__|_||_\__,_|  
"""

class VOLTHAClient(object):
    def __init__(self, voltha_grpc, global_request=False):
        self.voltha_grpc = voltha_grpc
        self.global_request = global_request
        self.channel = None
        self.stub = None
        self.log = structlog.get_logger()
        self.stdout = sys.stdout

    def get_channel(self):
        if self.channel is None:
            self.channel = grpc.insecure_channel(self.voltha_grpc)
        return self.channel

    def get_stub(self):
        if self.stub is None:
            self.stub = \
                voltha_pb2_grpc.VolthaGlobalServiceStub(self.get_channel()) \
                    if self.global_request else \
                    voltha_pb2_grpc.VolthaLocalServiceStub(self.get_channel())
        return self.stub

    def get_first_olt_device_id(self):
        """ Query VOLTHA and pick some olt device that we can use for alarms. """

        stub = self.get_stub()
        logical_devices = stub.ListLogicalDevices(Empty())
        logical_device_ids = [x.id for x in logical_devices.items]

        devices = stub.ListDevices(Empty())

        for device in devices.items:
            # If the parent_id is notempty and no a logical_device then it must not be an OLT.
            if (device.parent_id) and (device.parent_id not in logical_device_ids):
                print device.parent_id, logical_device_ids
                continue

            return device. id

        raise Exception("No OLT devices in VOLTHA to choose from")

    def get_onus(self, olt_id):
        """ Query VOLTHA to get a list of ONUs attached to a particular OLT """

        onus = []

        stub = self.get_stub()
        devices = stub.ListDevices(Empty())
        for device in devices.items:
            if device.parent_id != olt_id:
                continue
            if device.parent_port_no is None:
                continue

            onus.append({"id": olt_id,
                         "onu_device_id": device.id,
                         "intf_id": str(device.parent_port_no & 0x0F)})

        return onus


class AlarmGenerator(VOLTHAClient):
    def __init__(self, voltha_grpc, global_request, onus=[], rate=0.1, duration=1):
        super(AlarmGenerator, self).__init__(voltha_grpc, global_request)
        self.onus = onus
        self.rate = rate
        self.duration = duration
        self.raised_alarms = []

    def pick_alarm(self):
        eligible_indicators = ["dying_gasp", "onu_los", "onu_lopc_miss", "onu_lopc_mic", "onu_lob"]
        while True:
            onu = random.choice(self.onus)
            indicator = random.choice(eligible_indicators)

            alarm = copy.copy(onu)
            alarm["indicator"] = indicator

            # Make sure we don't already have this alarm raised on this ONU. If so, the loop around and try to pick
            # some other alarm. If all possible alarms are currently raised, eventually we'll keep looping until some
            # alarm is free.
            if alarm in self.raised_alarms:
                time.sleep(0.01)  # Avoid tying up the CPU if all alarms are raised for an extended time.
                continue

            return alarm

    def clear_alarm(self, kw):
        if kw in self.raised_alarms:
            self.raised_alarms.remove(kw)

        kw["operation"] = voltha_pb2.SimulateAlarmRequest.CLEAR

        response = None
        try:
            simulate_alarm = voltha_pb2.SimulateAlarmRequest(**kw)
            stub = self.get_stub()
            response = stub.SimulateAlarm(simulate_alarm)
        except Exception as e:
            self.log.error('Error simulate alarm {}. Error:{}'.format(kw['id'], e), kw=kw)
            return
        name = enum2name(common_pb2.OperationResp,
                        'OperationReturnCode', response.code)
        self.log.info("Cleared Alarm", alarm=kw, response=name)

    def generate_alarm(self):
        kw = self.pick_alarm()

        response = None
        try:
            simulate_alarm = voltha_pb2.SimulateAlarmRequest(**kw)
            stub = self.get_stub()
            response = stub.SimulateAlarm(simulate_alarm)
        except Exception as e:
            self.log.error('Error simulate alarm {}. Error:{}'.format(kw['id'], e), kw=kw)
            return
        name = enum2name(common_pb2.OperationResp,
                        'OperationReturnCode', response.code)
        self.log.info("Generated Alarm", alarm=kw, response=name)

        self.raised_alarms.append(kw)

        Timer(self.duration, functools.partial(self.clear_alarm, kw)).start()

    def run(self):
        while True:
            time.sleep(1/self.rate)
            self.generate_alarm()


def main():

    parser = argparse.ArgumentParser()

    _help = '<hostname>:<port> to consul agent (default: %s)' % defs['consul']
    parser.add_argument(
        '-C', '--consul', action='store', default=defs['consul'], help=_help)

    _help = 'Lookup Voltha endpoints based on service entries in Consul'
    parser.add_argument(
        '-L', '--lookup', action='store_true', help=_help)

    _help = 'All requests to the Voltha gRPC service are global'
    parser.add_argument(
        '-G', '--global_request', action='store_true', help=_help)

    _help = '<hostname>:<port> of Voltha gRPC service (default={})'.format(
        defs['voltha_grpc_endpoint'])
    parser.add_argument('-g', '--grpc-endpoint', action='store',
                        default=defs['voltha_grpc_endpoint'], help=_help)

    _help = 'device id, if None will query VOLTHA for the first device (default %s)' % defs['device_id']
    parser.add_argument('-d', '--device_id', action='store',
                        default=defs['device_id'], help=_help)

    _help = 'onu id, if None will query VOLTHA for a set of ONUs  (default: %s)' % defs['onu_id']
    parser.add_argument('-o', '--onu_id', action='store',
                        default=defs['onu_id'], help=_help)

    _help = 'intf id  (default: %s)' % defs['intf_id']
    parser.add_argument('-i', '--intf_id', action='store',
                        default=defs['intf_id'], help=_help)

    _help = 'rate in alarms per second  (default: %s)' % defs['rate']
    parser.add_argument('-r', '--rate', action='store', type=float,
                        default=defs['rate'], help=_help)

    _help = 'duration between raise and clear in seconds (default: %s)' % defs['duration']
    parser.add_argument('-u', '--duration', action='store', type=int,
                        default=defs['duration'], help=_help)

    args = parser.parse_args()

    if args.lookup:
        host = args.consul.split(':')[0].strip()
        port = int(args.consul.split(':')[1].strip())
        consul = Consul(host=host, port=port)

        _, services = consul.catalog.service('voltha-grpc')
        if not services:
            print('No voltha-grpc service registered in consul; exiting')
            sys.exit(1)
        args.grpc_endpoint = '{}:{}'.format(services[0]['ServiceAddress'],
                                            services[0]['ServicePort'])

        _, services = consul.catalog.service('voltha-sim-rest')
        if not services:
            print('No voltha-sim-rest service registered in consul; exiting')
            sys.exit(1)
        args.sim_rest_endpoint = '{}:{}'.format(services[0]['ServiceAddress'],
                                                services[0]['ServicePort'])

    device_id = args.device_id
    if not device_id:
        device_id = VOLTHAClient(args.grpc_endpoint, args.global_request).get_first_olt_device_id()

    if args.onu_id:
        onus = [{"id": device_id,
                 "onu_device_id": args.onu_id,
                 "intf_id": args.intf_id}]
    else:
        onus = VOLTHAClient(args.grpc_endpoint, args.global_request).get_onus(device_id)
        if not onus:
            raise Exception("Found no valid ONUs in VOLTHA on olt %s. Perhaps use -i and -o options?" % device_id)

    print banner

    g = AlarmGenerator(args.grpc_endpoint,
                       args.global_request,
                       onus = onus,
                       rate=args.rate,
                       duration=args.duration)
    g.run()

if __name__ == "__main__":
    main()
