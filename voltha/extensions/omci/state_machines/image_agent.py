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
import os
import structlog
from datetime import datetime, timedelta
from transitions import Machine
from twisted.internet import reactor, defer
from common.event_bus import EventBusClient
from voltha.protos.voltha_pb2 import ImageDownload
from voltha.protos.omci_mib_db_pb2 import OpenOmciEventType

class ImageDownloadeSTM(object):
    DEFAULT_STATES = ['disabled', 'downloading', 'validating', 'done']
    DEFAULT_TRANSITIONS = [
        {'trigger': 'start', 'source': 'disabled', 'dest': 'downloading'},
        {'trigger': 'stop',  'source': ['downloading', 'validating', 'done'], 'dest': 'disabled'},
        {'trigger': 'dw_success', 'source': 'downloading', 'dest': 'validating'},
        {'trigger': 'dw_fail', 'source': 'downloading', 'dest': 'done'},
        {'trigger': 'validate_success', 'source': 'validating', 'dest': 'done'},
    ]
    DEFAULT_TIMEOUT_RETRY = 10      # Seconds to delay after task failure/timeout

    def __init__(self, omci_agent, dev_id, local_name, local_dir, remote_url, download_task, 
                     states=DEFAULT_STATES,
                     transitions=DEFAULT_TRANSITIONS,
                     initial_state='disabled',
                     timeout_delay=DEFAULT_TIMEOUT_RETRY,
                     advertise_events=True):
        self.log = structlog.get_logger(device_id=dev_id)
        self._agent = omci_agent
        self._imgdw = ImageDownload()
        self._imgdw.name = local_name
        self._imgdw.id   = dev_id
        self._imgdw.url  = remote_url
        self._imgdw.local_dir = local_dir
        self._imgdw.state = ImageDownload.DOWNLOAD_UNKNOWN   # voltha_pb2

        self._download_task   = download_task
        self._timeout_delay   = timeout_delay

        self._current_task  = None
        self._task_deferred = None
        self._ret_deferred  = None
        self._timeout_deferred = None
        self._advertise_events = advertise_events

        self.machine = Machine(model=self, states=states,
                               transitions=transitions,
                               initial=initial_state,
                               queued=True,
                               name='{}-{}'.format(self.__class__.__name__, self._imgdw.id))
    @property
    def name(self):
        return self._imgdw.name

    @property
    def download_state(self):
        return self._imgdw.state

    def advertise(self, event, info):
        """Advertise an event on the OpenOMCI event bus"""
        if self._advertise_events:
            self._agent.advertise(event,
                                  {
                                      'state-machine': self.machine.name,
                                      'info': info,
                                      'time': str(datetime.utcnow())
                                  })

    def reset(self):
        """
        Reset all the state machine to intial state
        It is used to clear failed result in last downloading
        """
        self.log.debug('reset download: ', self._imgdw)
        if self._current_task is not None:
            self._current_task.stop()
            
        self._cancel_deferred()
        
        if self._ret_deferred is not None:
            self._ret_deferred.cancel()
            self._ret_deferred = None

        self.stop()
        self._imgdw.state = ImageDownload.DOWNLOAD_UNKNOWN

        
    def get_file(self):
        """
          return a defer.Deferred object
          Caller will register a callback to the Deferred to get notified once the image is available
        """
        self.log.debug('Get to work: {}'.format(self._imgdw))
        if self._ret_deferred is None or self._ret_deferred.called:
            self._ret_deferred = defer.Deferred()
            
        if self._imgdw.state == ImageDownload.DOWNLOAD_SUCCEEDED:
            self.log.debug('Image Available')
            reactor.callLater(0, self._ret_deferred.callback, self)
        elif self._imgdw.state == ImageDownload.DOWNLOAD_FAILED or self._imgdw.state == ImageDownload.DOWNLOAD_UNSUPPORTED:
            self.log.debug('Image not exist')
            reactor.callLater(0, self._ret_deferred.errback, self)
        elif self._imgdw.state == ImageDownload.DOWNLOAD_UNKNOWN:
            self.log.debug('Start Image STM')
            self._imgdw.state == ImageDownload.DOWNLOAD_STARTED
            reactor.callLater(0, self.start)
        else:
            pass
            
        return self._ret_deferred
            
    def _cancel_deferred(self):
        d1, self._timeout_deferred = self._timeout_deferred, None
        d2, self._task_deferred = self._task_deferred, None

        for d in [d1, d1]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    def timeout(self):
        self.log.debug('Image Download Timeout {}'.format(self._imgdw));
        if self._task_deferred is not None and not self._task_deferred.called:
            self._task_deferred.cancel()
        self._current_task = None
        self.dw_fail()
            
        
    def on_enter_disabled(self):
        self.advertise(OpenOmciEventType.state_change, self.state)
        #
        # remove local file fragments if download failed
        file_path = self._imgdw.local_dir + '/' + self._imgdw.name
        if self._imgdw.state != ImageDownload.DOWNLOAD_SUCCEEDED and os.path.exists(file_path):
            os.remove(file_path)            
        self._imgdw.state == ImageDownload.DOWNLOAD_UNKNOWN

    def on_enter_downloading(self):
        self.advertise(OpenOmciEventType.state_change, self.state)
        def success(results):
            self.log.debug('image-download-success', results=results)
            self._imgdw.state = ImageDownload.DOWNLOAD_SUCCEEDED
            self._current_task = None
            self.dw_success()

        def failure(reason):
            self.log.info('image-download-failure', reason=reason)
            self._imgdw.state = ImageDownload.FAILED
            self._current_task = None
            self.dw_fail()

        self._device = self._agent.get_device(self._imgdw.id)
        self._current_task = self._download_task(self._agent, self._imgdw.id, self._imgdw.url, 
                                                 '{}/{}'.format(self._imgdw.local_dir, self._imgdw.name))

        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)

        if self._timeout_delay > 0:
            self._timeout_deferred = reactor.callLater(self._timeout_delay, self.timeout)

    def on_enter_validating(self):
        self.advertise(OpenOmciEventType.state_change, self.state)
        self.validate_success()

    def on_enter_done(self):
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()
        
        if self._imgdw.state == ImageDownload.DOWNLOAD_SUCCEEDED:
            reactor.callLater(0, self._ret_deferred.callback, self)
        else:  # failed
            reactor.callLater(0, self._ret_deferred.errback, self)
    
class ImageAgent(object):
    """
        Image Agent supports multiple state machines running at the same time:
    """
    def __init__(self, omci_agent, dev_id, stm_cls, img_tasks, advertise_events=True):
        """
        Class initialization

        :param omci_agent: (OpenOmciAgent) Agent
        :param dev_id    : (str) ONU Device ID
        :param stm_cls   : (ImageDownloadeSTM) Image download state machine class
        :param img_tasks : (FileDownloadTask) file download task
        """
        
        self.log = structlog.get_logger(device_id=dev_id)

        self._omci_agent = omci_agent
        self._device_id = dev_id
        self._state_machine_cls   = stm_cls
        self._download_task = img_tasks['download-file'] 
        self._advertise_events = advertise_events
        self._images = dict()
        
    def get_image(self, name, local_dir, remote_url, timeout_delay=ImageDownloadeSTM.DEFAULT_TIMEOUT_RETRY):

        """
        Get named image from the agent
        
        :param name          : (str) filename or image name 
        :param local_dir     : (str) local directory where the image is saved. if image not exist, start downloading
        :param remote_url    : (str) the URL to download image
        :param timeout_delay : (number) timeout for download task
        :
        :Return a Deferred that will be triggered if the file is locally availabe or downloaded sucessfully
        :  Caller will register callback and errback to the returned defer to get notified
        """
        if name not in self._images.keys():
            self._images[name] = ImageDownloadeSTM(self._omci_agent, self._device_id, name, 
                                                   local_dir, remote_url, self._download_task,
                                                   timeout_delay=timeout_delay)
        elif self._images[name].download_state != ImageDownload.DOWNLOAD_SUCCEEDED:
            self._images[name].reset()
            
        d = self._images[name].get_file()
        # reactor.callLater(0, self._images[name].start)
        return d
        
