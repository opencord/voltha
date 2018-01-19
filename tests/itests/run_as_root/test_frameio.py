#!/usr/bin/env python
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
Run this test inside a docker container using the following syntax:

docker run -ti --rm -v $(pwd):/voltha  --privileged voltha/voltha-base \
    env PYTHONPATH=/voltha python \
    /voltha/tests/itests/run_as_root/test_frameio.py

"""

import os
import random
from time import sleep

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, Dot1Q
from twisted.internet import reactor
from twisted.internet.defer import Deferred, inlineCallbacks, DeferredQueue
from twisted.internet.error import AlreadyCalled
from twisted.trial.unittest import TestCase

from common.frameio.frameio import FrameIOManager, BpfProgramFilter, \
    FrameIOPortProxy, FrameIOPort
from common.utils.asleep import asleep
from common.utils.deferred_utils import DeferredWithTimeout, TimeOutError

ident = lambda frame: frame
none = lambda *args, **kw: None


class TestFrameIO(TestCase):
    @inlineCallbacks
    def make_veth_pairs_if_needed(self):

        def has_iface(iface):
            return os.system('ip link show {}'.format(iface)) == 0

        def make_veth(iface):
            os.system('ip link add type veth')
            os.system('ip link set {} up'.format(iface))
            peer = iface[:len('veth')] + str(int(iface[len('veth'):]) + 1)
            os.system('ip link set {} up'.format(peer))
            assert has_iface(iface)

        for iface_number in (0, 2):
            iface = 'veth{}'.format(iface_number)
            if not has_iface(iface):
                make_veth(iface)
                yield asleep(2)

    @inlineCallbacks
    def setUp(self):
        yield self.make_veth_pairs_if_needed()
        self.mgr = FrameIOManager().start()

    def tearDown(self):
        self.mgr.stop()

    @inlineCallbacks
    def test_packet_send_receive(self):
        rcvd = DeferredWithTimeout()
        p0 = self.mgr.open_port('veth0', none).up()
        p1 = self.mgr.open_port('veth1',
                                lambda p, f: rcvd.callback((p, f))).up()

        # sending to veth0 should result in receiving on veth1 and vice versa
        bogus_frame = 'bogus packet'
        bogus_frame_padded = bogus_frame + '\x00' * (
                                FrameIOPort.MIN_PKT_SIZE - len(bogus_frame))
        p0.send(bogus_frame_padded)

        # check that we receved packet
        port, frame = yield rcvd
        self.assertEqual(port, p1)
        self.assertEqual(frame, bogus_frame_padded)

    @inlineCallbacks
    def test_packet_send_receive_with_filter(self):
        rcvd = DeferredWithTimeout()

        filter = BpfProgramFilter('ip dst host 123.123.123.123')
        p0 = self.mgr.open_port('veth0', none).up()
        p1 = self.mgr.open_port('veth1',
                                lambda p, f: rcvd.callback((p, f)),
                                filter=filter).up()

        # sending bogus packet would not be received
        ip_packet = str(Ether() / IP(dst='123.123.123.123'))
        p0.send(ip_packet)

        # check that we receved packet
        port, frame = yield rcvd
        self.assertEqual(port, p1)
        self.assertEqual(frame, ip_packet)

    @inlineCallbacks
    def test_packet_send_drop_with_filter(self):
        rcvd = DeferredWithTimeout()

        filter = BpfProgramFilter('ip dst host 123.123.123.123')
        p0 = self.mgr.open_port('veth0', none).up()
        self.mgr.open_port('veth1', lambda p, f: rcvd.callback((p, f)),
                           filter=filter).up()

        # sending bogus packet would not be received
        p0.send('bogus packet')

        try:
            _ = yield rcvd
        except TimeOutError:
            pass
        else:
            self.fail('not timed out')

    @inlineCallbacks
    def test_concurrent_packet_send_receive(self):

        done = Deferred()
        queue1 = []
        queue2 = []

        n = 100

        def append(queue):
            def _append(_, frame):
                queue.append(frame)
                if len(queue1) == n and len(queue2) == n:
                    done.callback(None)

            return _append

        p1in = self.mgr.open_port('veth0', none).up()
        self.mgr.open_port('veth1', append(queue1)).up()
        p2in = self.mgr.open_port('veth2', none).up()
        self.mgr.open_port('veth3', append(queue2)).up()

        @inlineCallbacks
        def send_packets(port, n):
            for i in xrange(n):
                port.send(str(i))
                yield asleep(0.00001 * random.random())  # to interleave

        # sending two concurrent streams
        send_packets(p1in, n)
        send_packets(p2in, n)

        # verify that both queue got all packets
        yield done

    @inlineCallbacks
    def test_concurrent_packet_send_receive_with_filter(self):

        done = Deferred()
        queue1 = []
        queue2 = []

        n = 100

        def append(queue):
            def _append(_, frame):
                queue.append(frame)
                if len(queue1) == n / 2 and len(queue2) == n / 2:
                    done.callback(None)

            return _append

        filter = BpfProgramFilter('vlan 100')
        p1in = self.mgr.open_port('veth0', none).up()
        self.mgr.open_port('veth1', append(queue1), filter).up()
        p2in = self.mgr.open_port('veth2', none).up()
        self.mgr.open_port('veth3', append(queue2), filter).up()

        @inlineCallbacks
        def send_packets(port, n):
            for i in xrange(n):
                # packets have alternating VLAN ids 100 and 101
                pkt = Ether() / Dot1Q(vlan=100 + i % 2)
                port.send(str(pkt))
                yield asleep(0.00001 * random.random())  # to interleave

        # sending two concurrent streams
        send_packets(p1in, n)
        send_packets(p2in, n)

        # verify that both queue got all packets
        yield done

    @inlineCallbacks
    def test_shared_interface(self):

        queue1 = DeferredQueue()
        queue2 = DeferredQueue()

        # two senders hooked up to the same interface (sharing it)
        # here we test if they can both send
        pin1 = self.mgr.open_port('veth0', none).up()
        pin2 = self.mgr.open_port('veth0', none).up()

        pout1 = self.mgr.open_port(
            'veth1', lambda p, f: queue1.put((p, f))).up()
        filter = BpfProgramFilter('ip dst host 123.123.123.123')
        pout2 = self.mgr.open_port(
            'veth1', lambda p, f: queue2.put((p, f)), filter=filter).up()

        # sending from pin1, should be received by pout1
        bogus_frame = 'bogus packet'
        bogus_frame_padded = bogus_frame + '\x00' * (
                                FrameIOPort.MIN_PKT_SIZE - len(bogus_frame))
        pin1.send(bogus_frame_padded)
        port, frame = yield queue1.get()
        self.assertEqual(port, pout1)
        self.assertEqual(frame, bogus_frame_padded)
        self.assertEqual(len(queue1.pending), 0)
        self.assertEqual(len(queue2.pending), 0)

        # sending from pin2, should be received by pout1
        pin2.send(bogus_frame_padded)
        port, frame = yield queue1.get()
        self.assertEqual(port, pout1)
        self.assertEqual(frame, bogus_frame_padded)
        self.assertEqual(len(queue1.pending), 0)
        self.assertEqual(len(queue2.pending), 0)

        # sending from pin1, should be received by both pouts
        ip_packet = str(Ether() / IP(dst='123.123.123.123'))
        pin1.send(ip_packet)
        port, frame = yield queue1.get()
        self.assertEqual(port, pout1)
        self.assertEqual(frame, ip_packet)
        self.assertEqual(len(queue1.pending), 0)
        port, frame = yield queue2.get()
        self.assertEqual(port, pout2)
        self.assertEqual(frame, ip_packet)
        self.assertEqual(len(queue2.pending), 0)

        # sending from pin2, should be received by pout1
        ip_packet = str(Ether() / IP(dst='123.123.123.123'))
        pin2.send(ip_packet)
        port, frame = yield queue1.get()
        self.assertEqual(port, pout1)
        self.assertEqual(frame, ip_packet)
        self.assertEqual(len(queue1.pending), 0)
        port, frame = yield queue2.get()
        self.assertEqual(port, pout2)
        self.assertEqual(frame, ip_packet)
        self.assertEqual(len(queue2.pending), 0)

        self.mgr.close_port(pin1)
        self.mgr.close_port(pin2)
        self.mgr.close_port(pout1)
        self.mgr.close_port(pout2)


if __name__ == '__main__':
    import unittest

    unittest.main()
