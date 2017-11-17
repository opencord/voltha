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
A module that can send and receive raw ethernet frames on a set of interfaces
and it can manage a set of vlan interfaces on top of existing
interfaces. Due to reliance on raw sockets, this module requires
root access. Also, raw sockets are hard to deal with in Twisted (not
directly supported) we need to run the receiver select loop on a dedicated
thread.
"""

import os
import socket
import struct
import uuid
from pcapy import BPFProgram
from threading import Thread, Condition

import fcntl

import select
import structlog
import sys

from scapy.data import ETH_P_ALL
from twisted.internet import reactor
from zope.interface import implementer

from voltha.registry import IComponent

if sys.platform.startswith('linux'):
    from common.frameio.third_party.oftest import afpacket, netutils
elif sys.platform == 'darwin':
    from scapy.arch import pcapdnet, BIOCIMMEDIATE, dnet

log = structlog.get_logger()


def hexify(buffer):
    """
    Return a hexadecimal string encoding of input buffer
    """
    return ''.join('%02x' % ord(c) for c in buffer)


class _SelectWakerDescriptor(object):
    """
    A descriptor that can be mixed into a select loop to wake it up.
    """
    def __init__(self):
        self.pipe_read, self.pipe_write = os.pipe()
        fcntl.fcntl(self.pipe_write, fcntl.F_SETFL, os.O_NONBLOCK)

    def __del__(self):
        os.close(self.pipe_read)
        os.close(self.pipe_write)

    def fileno(self):
        return self.pipe_read

    def wait(self):
        os.read(self.pipe_read, 1)

    def notify(self):
        """Trigger a select loop"""
        os.write(self.pipe_write, '\x00')


class BpfProgramFilter(object):
    """
    Convenience packet filter based on the well-tried Berkeley Packet Filter,
    used by many well known open source tools such as pcap and tcpdump.
    """
    def __init__(self, program_string):
        """
        Create a filter using the BPF command syntax. To learn more,
        consult 'man pcap-filter'.
        :param program_string: The textual definition of the filter. Examples:
        'vlan 1000'
        'vlan 1000 and ip src host 10.10.10.10'
        """
        self.bpf = BPFProgram(program_string)

    def __call__(self, frame):
        """
        Return 1 if frame passes filter.
        :param frame: Raw frame provided as Python string
        :return: 1 if frame satisfies filter, 0 otherwise.
        """
        return self.bpf.filter(frame)


class FrameIOPort(object):
    """
    Represents a network interface which we can send/receive raw
    Ethernet frames.
    """

    RCV_SIZE_DEFAULT = 4096
    ETH_P_ALL = 0x03
    RCV_TIMEOUT = 10000
    MIN_PKT_SIZE = 60

    def __init__(self, iface_name):
        self.iface_name = iface_name
        self.proxies = []
        self.socket = self.open_socket(self.iface_name)
        log.debug('socket-opened', fn=self.fileno(), iface=iface_name)
        self.received = 0
        self.discarded = 0

    def add_proxy(self, proxy):
        self.proxies.append(proxy)

    def del_proxy(self, proxy):
        self.proxies = [p for p in self.proxies if p.name != proxy.name]

    def open_socket(self, iface_name):
        raise NotImplementedError('to be implemented by derived class')

    def rcv_frame(self):
        raise NotImplementedError('to be implemented by derived class')

    def __del__(self):
        if self.socket:
            self.socket.close()
            self.socket = None
        log.debug('socket-closed', iface=self.iface_name)

    def fileno(self):
        return self.socket.fileno()

    def _dispatch(self, proxy, frame):
        log.debug('calling-publisher', proxy=proxy.name, frame=hexify(frame))
        try:
            proxy.callback(proxy, frame)
        except Exception as e:
            log.exception('callback-error',
                          explanation='Callback failed while processing frame',
                          e=e)

    def recv(self):
        """Called on the select thread when a packet arrives"""
        try:
            frame = self.rcv_frame()
        except RuntimeError as e:
            # we observed this happens sometimes right after the socket was
            # attached to a newly created veth interface. So we log it, but
            # allow to continue.
            log.warn('afpacket-recv-error', code=-1)
            return

        log.debug('frame-received', iface=self.iface_name, len=len(frame),
                  hex=hexify(frame))
        self.received +=1
        dispatched = False
        for proxy in self.proxies:
            if proxy.filter is None or proxy.filter(frame):
                log.debug('frame-dispatched')
                dispatched = True
                reactor.callFromThread(self._dispatch, proxy, frame)

        if not dispatched:
            self.discarded += 1
            log.debug('frame-discarded')

    def send(self, frame):
        log.debug('sending', len=len(frame), iface=self.iface_name)
        sent_bytes = self.send_frame(frame)
        if sent_bytes != len(frame):
            log.error('send-error', iface=self.iface_name,
                      wanted_to_send=len(frame), actually_sent=sent_bytes)
        return sent_bytes

    def send_frame(self, frame):
        try:
            return self.socket.send(frame)
        except socket.error, err:
            if err[0] == os.errno.EINVAL:
                if len(frame) < self.MIN_PKT_SIZE:
                    padding = '\x00' * (self.MIN_PKT_SIZE - len(frame))
                    frame = frame + padding
                    return self.socket.send(frame)
            else:
                raise

    def up(self):
        if sys.platform.startswith('darwin'):
            pass
        else:
            os.system('ip link set {} up'.format(self.iface_name))
        return self

    def down(self):
        if sys.platform.startswith('darwin'):
            pass
        else:
            os.system('ip link set {} down'.format(self.iface_name))
        return self

    def statistics(self):
        return self.received, self.discarded


class LinuxFrameIOPort(FrameIOPort):

    def open_socket(self, iface_name):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        afpacket.enable_auxdata(s)
        s.bind((self.iface_name, self.ETH_P_ALL))
        netutils.set_promisc(s, iface_name)
        s.settimeout(self.RCV_TIMEOUT)
        return s

    def rcv_frame(self):
        return afpacket.recv(self.socket, self.RCV_SIZE_DEFAULT)


class DarwinFrameIOPort(FrameIOPort):

    def open_socket(self, iface_name):
        sin = pcapdnet.open_pcap(iface_name, 1600, 1, 100)
        try:
            fcntl.ioctl(sin.fileno(), BIOCIMMEDIATE, struct.pack("I",1))
        except:
            pass

        # need a different kind of socket for sending out
        self.sout = dnet.eth(iface_name)

        return sin

    def send_frame(self, frame):
        return self.sout.send(frame)

    def rcv_frame(self):
        pkt = self.socket.next()
        if pkt is not None:
            ts, pkt = pkt
        return pkt


if sys.platform == 'darwin':
    _FrameIOPort = DarwinFrameIOPort
elif sys.platform.startswith('linux'):
    _FrameIOPort = LinuxFrameIOPort
else:
    raise Exception('Unsupported platform {}'.format(sys.platform))
    sys.exit(1)


class FrameIOPortProxy(object):
    """Makes FrameIOPort sharable between multiple users"""

    def __init__(self, frame_io_port, callback, filter=None, name=None):
        self.frame_io_port = frame_io_port
        self.callback = callback
        self.filter = filter
        self.name = uuid.uuid4().hex[:12] if name is None else name

    @property
    def iface_name(self):
        return self.frame_io_port.iface_name

    def get_iface_name(self):
        return self.frame_io_port.iface_name

    def send(self, frame):
        return self.frame_io_port.send(frame)

    def up(self):
        self.frame_io_port.up()
        return self

    def down(self):
        self.frame_io_port.down()
        return self


@implementer(IComponent)
class FrameIOManager(Thread):
    """
    Packet/Frame IO manager that can be used to send/receive raw frames
    on a set of network interfaces.
    """
    def __init__(self):
        super(FrameIOManager, self).__init__()

        self.ports = {}  # iface_name -> ActiveFrameReceiver
        self.queue = {}  # iface_name -> TODO

        self.cvar = Condition()
        self.waker = _SelectWakerDescriptor()
        self.stopped = False
        self.ports_changed = False

    # ~~~~~~~~~~~ exposed methods callable from main thread ~~~~~~~~~~~~~~~~~~~

    def start(self):
        """
        Start the IO manager and its select loop thread
        """
        log.debug('starting')
        super(FrameIOManager, self).start()
        log.info('started')
        return self

    def stop(self):
        """
        Stop the IO manager and its thread with the select loop
        """
        log.debug('stopping')
        self.stopped = True
        self.waker.notify()
        self.join()
        del self.ports
        log.info('stopped')

    def list_interfaces(self):
        """
        Return list of interfaces listened on
        :return: List of FrameIOPort objects
        """
        return self.ports

    def open_port(self, iface_name, callback, filter=None, name=None):
        """
        Add a new interface and start receiving on it.
        :param iface_name: Name of the interface. Must be an existing Unix
        interface (eth0, en0, etc.)
        :param callback: Called on each received frame;
        signature: def callback(port, frame) where port is the FrameIOPort
        instance at which the frame was received, frame is the actual frame
        received (as binay string)
        :param filter: An optional filter (predicate), with signature:
        def filter(frame). If provided, only frames for which filter evaluates
        to True will be forwarded to callback.
        :return: FrmaeIOPortProxy instance.
        """

        port = self.ports.get(iface_name)
        if port is None:
            port = _FrameIOPort(iface_name)
            self.ports[iface_name] = port
            self.ports_changed = True
            self.waker.notify()

        proxy = FrameIOPortProxy(port, callback, filter, name)
        port.add_proxy(proxy)

        return proxy

    def close_port(self, proxy):
        """
        Remove the proxy. If this is the last proxy on an interface, stop and
        remove the named interface as well
        :param proxy: FrameIOPortProxy reference
        :return: None
        """
        assert isinstance(proxy, FrameIOPortProxy)
        iface_name = proxy.get_iface_name()
        assert iface_name in self.ports, "iface_name {} unknown".format(iface_name)
        port = self.ports[iface_name]
        port.del_proxy(proxy)

        if not port.proxies:
            del self.ports[iface_name]
            # need to exit select loop to reconstruct select fd lists
            self.ports_changed = True
            self.waker.notify()

    def send(self, iface_name, frame):
        """
        Send frame on given interface
        :param iface_name: Name of previously registered interface
        :param frame: frame as string
        :return: number of bytes sent
        """
        return self.ports[iface_name].send(frame)

    # ~~~~~~~~~~~~~ Thread methods (running on non-main thread ~~~~~~~~~~~~~~~~

    def run(self):
        """
        Called on the alien thread, this is the core multi-port receive loop
        """

        log.debug('select-loop-started')

        # outer loop constructs sockets list for select
        while not self.stopped:
            sockets = [self.waker] + self.ports.values()
            self.ports_changed = False
            empty = []
            # inner select loop

            while not self.stopped:
                try:
                    _in, _out, _err = select.select(sockets, empty, empty, 1)
                except Exception as e:
                    log.exception('frame-io-select-error', e=e)
                    break
                with self.cvar:
                    for port in _in:
                        if port is self.waker:
                            self.waker.wait()
                            continue
                        else:
                            port.recv()
                    self.cvar.notify_all()
                if self.ports_changed:
                    break  # break inner loop so we reconstruct sockets list

        log.debug('select-loop-exited')

    def del_interface(self, iface_name):
        """
            Delete interface for stopping
        """

        log.info('Delete interface')
        del self.ports[iface_name]
        log.info('Interface(port) is deleted')
