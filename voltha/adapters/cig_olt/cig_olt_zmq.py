#
# Copyright 2017-present CIG, Inc.
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
import binascii
import struct
import zmq
import sys
import thread
import time
import structlog

from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredQueue

log = structlog.get_logger()

zmq_context = zmq.Context()

#_OLTD_ZEROMQ_METRICS_PORT = 5555
_OLTD_ZEROMQ_SYNC_PORT = 5555

_OLTD_ZEROMQ_PACKET_OUT_PORT = 8889
_OLTD_ZEROMQ_OMCI_PORT = 8888
_OLTD_ZEROMQ_ASYNC_PORT = 6666

_OLTD_ZEROMQ_PUB_PACKET_IN_PORT = 7778
_OLTD_ZEROMQ_PUB_OMCI_PORT = 7777
_OLTD_ZEROMQ_PUB_OTHER_PORT = 4444

class CigZmqClientPollMetrics(object):
    """
    poll metrics ipc.
    """
    def __init__(self, ip_address, rx_incoming_queue):
        raise NotImplementedError(self)
        
    def poll_metrics_send(self, data):
        raise NotImplementedError(self)

class CigZmqClientSync(object):
    """
    Sync ipc.
    """
    def __init__(self, ip_address, rx_incoming_queue):
        self.external_conn = "tcp://{}:{}".format(ip_address, _OLTD_ZEROMQ_SYNC_PORT)
        self.socket = zmq_context.socket(zmq.REQ)
        self.socket.setsockopt(zmq.RCVTIMEO,3000)
        self.socket.connect(self.external_conn)
        self.rx_incoming_queue = rx_incoming_queue
        self.response = None

    def sync_send(self, data, flag=0):
        try:
            if flag == 1:
                self.socket.send(data, flags=zmq.SNDMORE)
            else:
                self.socket.send(data)
            if flag != 1:
                #try:
                thread.start_new_thread(self.sync_receive,())
                #except:
                #    log.exception(e.message)
            
        except Exception as e:
            log.exception(e.message)

    def sync_receive(self):

        try:
            self.response = self.socket.recv_multipart()
            self.rx_incoming_queue.put(self.response)

        except Exception as e:
            self.rx_incoming_queue.put("RecvTimeoutErr.")
            log.exception(e.message)

    def sync_reconnect(self):
        self.socket.close()
        self.socket = zmq_context.socket(zmq.REQ)
        self.socket.setsockopt(zmq.RCVTIMEO,3000)
        self.socket.connect(self.external_conn)


    def sync_shutdown(self):
        self.socket.close()


class CigZmqClientOmci(object):
    """
    Omci ipc.
    """
    def __init__(self, ip_address, rx_incoming_queue):

        self.external_conn_tx = "tcp://{}:{}".format(ip_address, _OLTD_ZEROMQ_OMCI_PORT)
        self.socket_tx = zmq_context.socket(zmq.DEALER)
        self.socket_tx.connect(self.external_conn_tx)

        self.external_conn_rx = "tcp://{}:{}".format(ip_address, _OLTD_ZEROMQ_PUB_OMCI_PORT)
        self.socket_rx = zmq_context.socket(zmq.SUB)
        self.socket_rx.setsockopt(zmq.SUBSCRIBE,'')
        self.socket_rx.setsockopt(zmq.RCVTIMEO,1000)
        self.socket_rx.connect(self.external_conn_rx)
        #self.rx_callback = rx_callback
        self.rx_incoming_queue = rx_incoming_queue
        self.killflag = 0
        
        try:
            thread.start_new_thread(self.omci_receive,())
        except:
            log.exception(e.message)
        
    def omci_send(self, data, flag=0):
        try:
            if flag == 1:
                self.socket_tx.send(data, flags=zmq.SNDMORE)
            else:
                self.socket_tx.send(data)

        except Exception as e:
            log.exception(e.message)
            
    def omci_receive(self):
        while True:
            #time.sleep(0.5)
            try:
                self.response = self.socket_rx.recv_multipart()
                #self.rx_callback(self.response)
                #log.info('omci_receive', self.response)
                self.rx_incoming_queue.put(self.response)

            except Exception as e:
                if self.killflag == 1:
                    thread.exit ()
                #log.exception('Exception during omci_receive processing', e=e)

    def omci_shutdown(self):
        self.killflag = 1
        time.sleep(1)
        self.socket_tx.close()
        self.socket_rx.close()

                

class CigZmqClientAsync(object):
    """
    Async ipc.
    """
    def __init__(self, ip_address, rx_callback):
       
        self.external_conn = "tcp://{}:{}".format(ip_address, _OLTD_ZEROMQ_ASYNC_PORT)
        self.socket = zmq_context.socket(zmq.DEALER)
        self.socket.setsockopt(zmq.RCVTIMEO,1000)
        self.socket.connect(self.external_conn)
        self.rx_callback = rx_callback
        #self.rx_incoming_queue = rx_incoming_queue
        self.killflag = 0
        
        try:
            thread.start_new_thread(self.async_receive,())
        except:
            log.exception(e.message)
        
    def async_send(self, data, flag=0):
        try:
            if flag == 1:
                self.socket.send(data, flags=zmq.SNDMORE)
            else:
                self.socket.send(data)

        except Exception as e:
            log.exception(e.message)
        
    def async_receive(self):
        while True:
            try:
                self.response = self.socket.recv_multipart()
                #self.rx_incoming_queue.put(self.response)
                self.rx_callback(self.response)
                #log.info('async_receive', self.response)
                
            except Exception as e:
                if self.killflag == 1:
                    thread.exit ()
                #log.exception('Exception during sync_receive processing', e=e)

    def async_shutdown(self):
        self.killflag = 1
        time.sleep(1)
        self.socket.close()


class CigZmqClientSub(object):
    """
    Publish ipc.
    """

    def __init__(self, ip_address, rx_incoming_queue):
        self.external_conn = "tcp://{}:{}".format(ip_address, _OLTD_ZEROMQ_PUB_OTHER_PORT)
        self.socket = zmq_context.socket(zmq.SUB)
        self.socket.setsockopt(zmq.SUBSCRIBE,'')
        self.socket.setsockopt(zmq.RCVHWM,10000)
        self.socket.setsockopt(zmq.RCVTIMEO,1000)
        self.socket.connect(self.external_conn)
        self.rx_incoming_queue = rx_incoming_queue
        self.killflag = 0
        
        log.info('CigZmqClientSub zmq.RCVHWM', self.socket.getsockopt(zmq.RCVHWM))
        
        try:
            thread.start_new_thread(self.sub_receive,())
        except:
            log.exception(e.message)

    def sub_receive(self):
        while True:
            try:
                self.response = self.socket.recv_multipart()
                #log.info('sub_receive', self.response)
                self.rx_incoming_queue.put(self.response)
            except Exception as e:
                if self.killflag == 1:
                    thread.exit ()
                #log.exception('Exception during sub_receive processing', e=e)

    def sub_shutdown(self):
        self.killflag = 1
        time.sleep(1)
        self.socket.close()

class CigZmqClientPacketInOut(object):
    """
    packet in/out ipc.
    """
    def __init__(self, ip_address, rx_incoming_queue):

        self.external_conn_tx = "tcp://{}:{}".format(ip_address, _OLTD_ZEROMQ_PACKET_OUT_PORT)
        self.socket_tx = zmq_context.socket(zmq.DEALER)
        self.socket_tx.connect(self.external_conn_tx)

        self.external_conn_rx = "tcp://{}:{}".format(ip_address, _OLTD_ZEROMQ_PUB_PACKET_IN_PORT)
        self.socket_rx = zmq_context.socket(zmq.SUB)
        self.socket_rx.setsockopt(zmq.SUBSCRIBE,'')
        self.socket_rx.setsockopt(zmq.RCVTIMEO,1000)
        self.socket_rx.connect(self.external_conn_rx)
        #self.rx_callback = rx_callback
        self.rx_incoming_queue = rx_incoming_queue
        self.killflag = 0
        
        try:
            thread.start_new_thread(self.packet_receive,())
        except:
            log.exception(e.message)
        
    def packet_send(self, data, flag=0):
        try:
            if flag == 1:
                self.socket_tx.send(data, flags=zmq.SNDMORE)
            else:
                self.socket_tx.send(data)

        except Exception as e:
            log.exception(e.message)
            
    def packet_receive(self):
        while True:
            #time.sleep(0.5)
            try:
                self.response = self.socket_rx.recv_multipart()
                #self.rx_callback(self.response)
                #log.info('packet_receive', self.response)
                self.rx_incoming_queue.put(self.response)

            except Exception as e:
                if self.killflag == 1:
                    thread.exit ()
                #log.exception('Exception during omci_receive processing', e=e)

    def packet_shutdown(self):
        self.killflag = 1
        time.sleep(1)
        self.socket_rx.close()
        self.socket_tx.close()


