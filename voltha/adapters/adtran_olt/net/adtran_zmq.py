# Copyright 2017-present Adtran, Inc.
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

import sys
import structlog

from twisted.internet.defer import succeed
from twisted.internet import threads

from txzmq import ZmqEndpoint, ZmqFactory
from txzmq.connection import ZmqConnection

import zmq
from zmq import constants
from zmq.utils import jsonapi
from zmq.utils.strtypes import b, u
from zmq.auth.base import Authenticator

from threading import Thread, Event

zmq_factory = ZmqFactory()


class AdtranZmqClient(object):
    """
    Adtran ZeroMQ Client for PON Agent and/or packet in/out service
    """
    def __init__(self, ip_address, rx_callback, port):
        self.log = structlog.get_logger()

        external_conn = 'tcp://{}:{}'.format(ip_address, port)

        self.zmq_endpoint = ZmqEndpoint('connect', external_conn)
        self._socket = ZmqPairConnection(zmq_factory, self.zmq_endpoint)
        self._socket.onReceive = rx_callback or AdtranZmqClient.rx_nop
        self.auth = None

    def send(self, data):
        try:
            self._socket.send(data)

        except Exception as e:
            self.log.exception('send', e=e)

    def shutdown(self):
        self._socket.onReceive = AdtranZmqClient.rx_nop
        self._socket.shutdown()

    @property
    def socket(self):
        return self._socket

    @staticmethod
    def rx_nop(_):
        pass

    def setup_plain_security(self, username, password):
        self.log.debug('setup-plain-security')

        def configure_plain(_):
            self.log.debug('plain-security', username=username,
                           password=password)

            self.auth.configure_plain(domain='*', passwords={username: password})
            self._socket.socket.plain_username = username
            self._socket.socket.plain_password = password

        def add_endoints(_results):
            self._socket.addEndpoints([self.zmq_endpoint])

        def config_failure(_results):
            raise Exception('Failed to configure plain-text security')

        def endpoint_failure(_results):
            raise Exception('Failed to complete endpoint setup')

        self.auth = TwistedZmqAuthenticator()

        d = self.auth.start()
        d.addCallbacks(configure_plain, config_failure)
        d.addCallbacks(add_endoints, endpoint_failure)

        return d

    def setup_curve_security(self):
        self.log.debug('setup-curve-security')
        raise NotImplementedError('TODO: curve transport security is not yet supported')


class ZmqPairConnection(ZmqConnection):
    """
    Bidirectional messages to/from the socket.

    Wrapper around ZeroMQ PUSH socket.
    """
    socketType = constants.PAIR

    def messageReceived(self, message):
        """
        Called on incoming message from ZeroMQ.

        :param message: message data
        """
        self.onReceive(message)

    def onReceive(self, message):
        """
        Called on incoming message received from other end of the pair.

        :param message: message data
        """
        raise NotImplementedError(self)

    def send(self, message):
        """
        Send message via ZeroMQ socket.

        Sending is performed directly to ZeroMQ without queueing. If HWM is
        reached on ZeroMQ side, sending operation is aborted with exception
        from ZeroMQ (EAGAIN).

        After writing read is scheduled as ZeroMQ may not signal incoming
        messages after we touched socket with write request.

        :param message: message data, could be either list of str (multipart
            message) or just str
        :type message: str or list of str
        """
        from txzmq.compat import is_nonstr_iter
        from twisted.internet import reactor

        if not is_nonstr_iter(message):
            self.socket.send(message, constants.NOBLOCK)
        else:
            # for m in message[:-1]:
            #     self.socket.send(m, constants.NOBLOCK | constants.SNDMORE)
            # self.socket.send(message[-1], constants.NOBLOCK)
            self.socket.send_multipart(message, flags=constants.NOBLOCK)

        if self.read_scheduled is None:
            self.read_scheduled = reactor.callLater(0, self.doRead)

###############################################################################################
###############################################################################################
###############################################################################################
###############################################################################################


def _inherit_docstrings(cls):
    """inherit docstrings from Authenticator, so we don't duplicate them"""
    for name, method in cls.__dict__.items():
        if name.startswith('_'):
            continue
        upstream_method = getattr(Authenticator, name, None)
        if not method.__doc__:
            method.__doc__ = upstream_method.__doc__
    return cls


@_inherit_docstrings
class TwistedZmqAuthenticator(object):
    """Run ZAP authentication in a background thread but communicate via Twisted ZMQ"""

    def __init__(self, encoding='utf-8'):
        self.log = structlog.get_logger()
        self.context = zmq_factory.context
        self.encoding = encoding
        self.pipe = None
        self.pipe_endpoint = "inproc://{0}.inproc".format(id(self))
        self.thread = None

    def allow(self, *addresses):
        try:
            self.pipe.send([b'ALLOW'] + [b(a, self.encoding) for a in addresses])

        except Exception as e:
            self.log.exception('allow', e=e)

    def deny(self, *addresses):
        try:
            self.pipe.send([b'DENY'] + [b(a, self.encoding) for a in addresses])

        except Exception as e:
            self.log.exception('deny', e=e)

    def configure_plain(self, domain='*', passwords=None):
        try:
            self.pipe.send([b'PLAIN', b(domain, self.encoding), jsonapi.dumps(passwords or {})])

        except Exception as e:
            self.log.exception('configure-plain', e=e)

    def configure_curve(self, domain='*', location=''):
        try:
            domain = b(domain, self.encoding)
            location = b(location, self.encoding)
            self.pipe.send([b'CURVE', domain, location])

        except Exception as e:
            self.log.exception('configure-curve', e=e)

    def start(self, rx_callback=AdtranZmqClient.rx_nop):
        """Start the authentication thread"""
        try:
            # create a socket to communicate with auth thread.

            endpoint = ZmqEndpoint('bind', self.pipe_endpoint)      # We are server, thread will be client
            self.pipe = ZmqPairConnection(zmq_factory, endpoint)
            self.pipe.onReceive = rx_callback

            self.thread = LocalAuthenticationThread(self.context,
                                                    self.pipe_endpoint,
                                                    encoding=self.encoding)

            return threads.deferToThread(TwistedZmqAuthenticator._do_thread_start,
                                         self.thread, timeout=10)

        except Exception as e:
            self.log.exception('start', e=e)

    @staticmethod
    def _do_thread_start(thread, timeout=10):
        thread.start()

        # Event.wait:Changed in version 2.7: Previously, the method always returned None.
        if sys.version_info < (2, 7):
            thread.started.wait(timeout=timeout)

        elif not thread.started.wait(timeout=timeout):
            raise RuntimeError("Authenticator thread failed to start")

    def stop(self):
        """Stop the authentication thread"""
        pipe, self.pipe = self.pipe, None
        thread, self.thread = self.thread, None

        if pipe:
            pipe.send(b'TERMINATE')
            pipe.onReceive = AdtranZmqClient.rx_nop
            pipe.shutdown()

            if thread.is_alive():
                return threads.deferToThread(TwistedZmqAuthenticator._do_thread_join,
                                             thread)
        return succeed('done')

    @staticmethod
    def _do_thread_join(thread, timeout=1):
        thread.join(timeout)
        pass

    def is_alive(self):
        """Is the ZAP thread currently running?"""
        return self.thread and self.thread.is_alive()

    def __del__(self):
        self.stop()


# NOTE: Following is a duplicated from zmq code since class was not exported
class LocalAuthenticationThread(Thread):
    """A Thread for running a zmq Authenticator

    This is run in the background by ThreadedAuthenticator
    """

    def __init__(self, context, endpoint, encoding='utf-8', authenticator=None):
        super(LocalAuthenticationThread, self).__init__(name='0mq Authenticator')
        self.log = structlog.get_logger()
        self.context = context or zmq.Context.instance()
        self.encoding = encoding
        self.started = Event()
        self.authenticator = authenticator or Authenticator(context, encoding=encoding)

        # create a socket to communicate back to main thread.
        self.pipe = context.socket(zmq.PAIR)
        self.pipe.linger = 1
        self.pipe.connect(endpoint)

    def run(self):
        """Start the Authentication Agent thread task"""
        try:
            self.authenticator.start()
            self.started.set()
            zap = self.authenticator.zap_socket
            poller = zmq.Poller()
            poller.register(self.pipe, zmq.POLLIN)
            poller.register(zap, zmq.POLLIN)
            while True:
                try:
                    socks = dict(poller.poll())
                except zmq.ZMQError:
                    break  # interrupted

                if self.pipe in socks and socks[self.pipe] == zmq.POLLIN:
                    terminate = self._handle_pipe()
                    if terminate:
                        break

                if zap in socks and socks[zap] == zmq.POLLIN:
                    self._handle_zap()

            self.pipe.close()
            self.authenticator.stop()

        except Exception as e:
            self.log.exception("run", e=e)

    def _handle_zap(self):
        """
        Handle a message from the ZAP socket.
        """
        msg = self.authenticator.zap_socket.recv_multipart()
        if not msg:
            return
        self.authenticator.handle_zap_message(msg)

    def _handle_pipe(self):
        """
        Handle a message from front-end API.
        """
        terminate = False

        # Get the whole message off the pipe in one go
        msg = self.pipe.recv_multipart()

        if msg is None:
            terminate = True
            return terminate

        command = msg[0]
        self.log.debug("auth received API command", command=command)

        if command == b'ALLOW':
            addresses = [u(m, self.encoding) for m in msg[1:]]
            try:
                self.authenticator.allow(*addresses)
            except Exception as e:
                self.log.exception("Failed to allow", addresses=addresses, e=e)

        elif command == b'DENY':
            addresses = [u(m, self.encoding) for m in msg[1:]]
            try:
                self.authenticator.deny(*addresses)
            except Exception as e:
                self.log.exception("Failed to deny", addresses=addresses, e=e)

        elif command == b'PLAIN':
            domain = u(msg[1], self.encoding)
            json_passwords = msg[2]
            self.authenticator.configure_plain(domain, jsonapi.loads(json_passwords))

        elif command == b'CURVE':
            # For now we don't do anything with domains
            domain = u(msg[1], self.encoding)

            # If location is CURVE_ALLOW_ANY, allow all clients. Otherwise
            # treat location as a directory that holds the certificates.
            location = u(msg[2], self.encoding)
            self.authenticator.configure_curve(domain, location)

        elif command == b'TERMINATE':
            terminate = True

        else:
            self.log.error("Invalid auth command from API", command=command)

        return terminate
