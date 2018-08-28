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
from binascii import crc32
from transitions import Machine
from transitions.extensions.nesting import HierarchicalMachine as HMachine
from twisted.python import failure
from twisted.internet import reactor, defer
from common.event_bus import EventBusClient
from voltha.protos.voltha_pb2 import ImageDownload
from voltha.protos.omci_mib_db_pb2 import OpenOmciEventType
from voltha.extensions.omci.omci_defs import EntityOperations, ReasonCodes, AttributeAccess, OmciSectionDataSize
from voltha.extensions.omci.omci_entities import SoftwareImage
from voltha.extensions.omci.omci_cc import DEFAULT_OMCI_TIMEOUT

###################################################################################
##              OLT out-of-band download image procedure
###################################################################################

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
        print("on_enter_done")
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_deferred()
        
        if self._imgdw.state == ImageDownload.DOWNLOAD_SUCCEEDED:
            reactor.callLater(0, self._ret_deferred.callback, self)
        else:  # failed
            reactor.callLater(0, self._ret_deferred.errback, self)
            
###################################################################################
##              OMCI Software Image Download Procedure
###################################################################################

class OmciSoftwareImageDownloadSTM(object):
    
    OMCI_SWIMG_DOWNLOAD_TIMEOUT = 1800      # Seconds for the full downloading procedure to avoid errors that cause infinte downloading
    OMCI_SWIMG_DOWNLOAD_WINDOW_SIZE = 4
    OMCI_SWIMG_WINDOW_RETRY_MAX = 2

    # def __init__(self, omci_agent, dev_id, img_path, 
    def __init__(self, omci_agent, dev_id,
                     window_size=OMCI_SWIMG_DOWNLOAD_WINDOW_SIZE,
                     timeout_delay=OMCI_SWIMG_DOWNLOAD_TIMEOUT,
                     advertise_events=True,
                     clock=None):
        self._dev_id = dev_id
        self._timeout = timeout_delay
        self._window_size = window_size
        self.reactor = clock if clock is not None else reactor
        self._offset = 0
        self._win_section = 0
        self._win_retry   = 0
        self._omci_agent = omci_agent
        self._device = omci_agent.get_device(dev_id)
        self.__init_state_machine()
        self._ret_deferred = None
        self._instance_id = None
        self._image_file = None
        self._image_fd   = None
        self._image_size = 0
        self._crc32 = 0
        self._win_crc32 = 0
        self._current_deferred = None
        self._result = None    # ReasonCodes

    def __init_state_machine(self):
        OMCI_DOWNLOAD_WINDOW_STATE = ['init_window', 'sending_sections', 'window_success', 'window_failed']
        OMCI_DOWNLOAD_WINDOW_TRANSITIONS = [
            {'trigger': 'send_sections',  'source': 'init_window',     'dest': 'sending_sections'},
            # {'trigger': 'send_section_last',  'source': 'start_section', 'dest': 'last_section'  },
            {'trigger': 'rx_ack_success', 'source': 'sending_sections', 'dest': 'window_success' },
            {'trigger': 'rx_ack_failed',  'source': 'sending_sections', 'dest': 'window_failed'  },
            # {'trigger': 'retry_window',   'source': 'window_failed', 'dest': 'start_section'  },
            {'trigger': 'reset_window',   'source': '*',               'dest': 'init_window'    }
        ]    
        self.win_machine = HMachine(model=self, 
                                   states=OMCI_DOWNLOAD_WINDOW_STATE,
                                   transitions=OMCI_DOWNLOAD_WINDOW_TRANSITIONS,
                                   initial='init_window',
                                   queued=True,
                                   name='{}-window_section_machine'.format(self.__class__.__name__))
                                   
        OMCI_SWIMG_DOWNLOAD_STATES = ['init_image', 'starting_image', {'name': 'dwin', 'children': self.win_machine}, 'ending_image', 'done_image']
        OMCI_SWIMG_DOWNLOAD_TRANSITIONS = [
            {'trigger': 'start_image',      'source': 'init_image',     'dest': 'starting_image' },
            {'trigger': 'download_window',  'source': 'starting_image', 'dest': 'dwin'           },
            {'trigger': 'download_success', 'source': 'dwin',           'dest': 'ending_image'   },
            {'trigger': 'end_img_success',  'source': 'ending_image',   'dest': 'done_image'     },
            # {'trigger': 'download_fail',    'source': 'dwin',           'dest': 'done_image'     },
            {'trigger': 'end_img_fail',     'source': 'ending_image',   'dest': 'done_image'     },
            {'trigger': 'download_fail',    'source': ['starting_image',  'dwin', 'ending_image'], 'dest': 'done_image'},
            {'trigger': 'reset_image',      'source': '*',              'dest': 'init_image'     },
        ]
        
        self.img_machine = HMachine(model=self, 
                                   states=OMCI_SWIMG_DOWNLOAD_STATES,
                                   transitions=OMCI_SWIMG_DOWNLOAD_TRANSITIONS,
                                   initial='init_image',
                                   queued=True,
                                   name='{}-image_download_machine'.format(self.__class__.__name__))

    @property
    def instance_id(self):
        return self._instance_id

    @instance_id.setter
    def instance_id(self, value):
        self._instance_id = value

    @property
    def image_filename(self):
        return self._image_file

    @image_filename.setter
    def image_filename(self, value):
        if self._image_fd is not None:
            self._image_fd.close()
        self._image_filename = value
        self._image_fd = open(self._image_filename, mode='rb')
        self._image_size = os.path.getsize(self._image_filename)
        print("Set image file: " + self._image_filename + " size: " + str(self._image_size))

    def __omci_resp_success(self, rx_frame, cur_state):
        print("__omci_resp_success: " + cur_state)
        if cur_state == 'starting_image':
            self.download_window()
        elif cur_state == 'ending_image':
            self._result = ReasonCodes.Success
            self.end_img_success()
        return rx_frame

    def __omci_resp_fail(self, fail, cur_state):
        print("__omci_resp_fail: " + cur_state)
        if cur_state == 'starting_image':
            self._result = ReasonCodes.ProcessingError
            self.download_fail()
        elif cur_state == 'ending_image':
            self._result = ReasonCodes.ProcessingError
            self.download_fail()

    def __omci_send_window_resp_success(self, rx_frame, state, datasize):
        print("__omci_send_window_resp_success: " + str(datasize))
        self._offset += datasize
        self.rx_ack_success()

    def __omci_send_window_resp_fail(self, fail, state):
        print("__omci_send_window_resp_fail: " + state)
        self.rx_ack_failed()

    def start(self):
        print("OmciSoftwareImageDownloadSTM.start: " + self.state)
        if self._ret_deferred is None:
            self._ret_deferred = defer.Deferred()
        if self.state == 'init_image':
            self.reactor.callLater(0, self.start_image)
        return self._ret_deferred
        
    def on_enter_init_image(self):
        self._image_file.seek(0)
        self._offset = 0
        self._win_section = 0
        self._win_retry   = 0
        
    def on_enter_starting_image(self):
        print("--> on_enter_starting_image")
        self._current_deferred = self._device.omci_cc.send_start_software_download(self._instance_id, self._image_size)
        self._current_deferred.addCallbacks(self.__omci_resp_success, self.__omci_resp_fail,
                                            callbackArgs=(self.state,), errbackArgs=(self.state,))

    def on_enter_dwin_init_window(self):
        print("--> on_enter_dwin_init_window")
        if self._offset < self._image_size:
            self._win_crc32 = 0
            self.send_sections()

    def on_enter_dwin_sending_sections(self):
        print("--> on_enter_dwin_sending_sections")
        print("offset: " + str(self._offset) + " window size: " + str(self._window_size))

        if (self._offset + self._window_size * OmciSectionDataSize) <= self._image_size:
            sections = self._window_size
            mod = 0
            datasize = self._window_size * OmciSectionDataSize
        else:
            datasize = self._image_size - self._offset
            sections = datasize / OmciSectionDataSize
            mod = datasize % OmciSectionDataSize
            sections = sections + 1 if mod > 0 else sections

        print("data size: " + str(datasize) + ", sections: " + str(sections))
        data = self._image_fd.read(datasize)
        self._win_crc32 = crc32(data, self._crc32) & 0xFFFFFFFF
        
        # print(data)
        sent = 0
        for i in range(0, sections):
            print
            if i < sections - 1:
                # print(data[self._offset+sent:self._offset+sent+OmciSectionDataSize])
                self._device.omci_cc.send_download_section(self._instance_id, self._win_section+i,
                                                           data[self._offset+sent:self._offset+sent+OmciSectionDataSize])
                sent += OmciSectionDataSize
            else:
                last_size = OmciSectionDataSize if mod == 0 else mod
                # print(data[self._offset+sent:self._offset+sent+last_size])
                self._current_deferred = self._device.omci_cc.send_download_section(self._instance_id, self._win_section+i,
                                                           data[self._offset+sent:self._offset+sent+last_size],
                                                           timeout=DEFAULT_OMCI_TIMEOUT)
                self._current_deferred.addCallbacks(self.__omci_send_window_resp_success, self.__omci_send_window_resp_fail,
                                                    callbackArgs=(self.state, datasize), errbackArgs=(self.state,))
                sent += last_size
                assert sent==datasize

    # def on_enter_dwin_last_section(self):
    #     self._current_deferred = self._device.omci_cc.send_download_section, self._instance_id, self._win_section, data)
    #     self._current_deferred.addCallbacks(self.__omci_resp_success, self.__omci_resp_fail,
    #                                         callbackArgs=(self.state,), errbackArgs=(self.state,))

    def on_enter_dwin_window_success(self):
        print("--> on_enter_dwin_window_success")
        if self._offset < self._image_size:
            self._crc32 = self._win_crc32 if self._win_crc32 != 0 else self._crc32
            self.reset_window()
        else:
            self.download_success()

    def on_enter_dwin_window_failed(self):
        print("--> on_enter_dwin_window_fail: retry " + str(self._win_retry))
        if self._win_retry < self.OMCI_SWIMG_WINDOW_RETRY_MAX:
            self._win_retry += 1
            self.reset_window()
        else:
            self._result = ReasonCodes.ProcessingError
            self.download_fail()

    def on_enter_ending_image(self):
        print("--> on_enter_ending_image: %08X" % self._crc32)
        self._current_deferred = self._device.omci_cc.send_end_software_download(self._instance_id, self._crc32, self._image_size)
        self._current_deferred.addCallbacks(self.__omci_resp_success, self.__omci_resp_fail,
                                            callbackArgs=(self.state,), errbackArgs=(self.state,))

    def on_enter_done_image(self):
        print("--> on_enter_done_image: " + str(self._result))
        if self._result == ReasonCodes.Success:
            self._ret_deferred.callback(str(self._instance_id))
        else:
            self._ret_deferred.errback(failure.Failure(Exception('ONU Software Download Failed, instance ' + str(self._instance_id))))

###################################################################################
##              OMCI Software Image Activation/Committing Procedure
###################################################################################

class OmciSoftwareImageActivateSTM(object):
    OMCI_SWIMG_ACTIVATE_STATES = ['starting', 'activating', 'rebooting', 'committing', 'done', 'failed']
    OMCI_SWIMG_ACTIVATE_TRANSITIONS = [
        {'trigger': 'activate', 'source': 'starting', 'dest': 'activating'},
        {'trigger': 'reboot',   'source': 'activating', 'dest': 'rebooting'},
        {'trigger': 'bootup',   'source': 'rebooting', 'dest': 'committing'},
        {'trigger': 'commit_ok','source': 'committing', 'dest': 'done'},
        {'trigger': 'reset',    'source': ['activating', 'rebooting', 'committing', 'failed'], 'dest': 'starting'},
        {'trigger': 'fail',     'source': ['activating', 'rebooting', 'committing'], 'dest': 'failed'}
    ]
    OMCI_SWIMG_ACTIVATE_TRANSITIONS_TIMEOUT = 10      # Seconds to delay after task failure/timeout
    OMCI_SWIMG_ACTIVATE_RETRY_MAX           = 2
    def __init__(self, omci_agent, dev_id, target_img_entity_id,
                     states=OMCI_SWIMG_ACTIVATE_STATES,
                     transitions=OMCI_SWIMG_ACTIVATE_TRANSITIONS,
                     initial_state='disabled',
                     timeout_delay=OMCI_SWIMG_ACTIVATE_TRANSITIONS_TIMEOUT,
                     advertise_events=True,
                     clock=None):

        self._omci_agent = omci_agent
        self._device_id  = dev_id
        self._device = omci_agent.get_device(dev_id)
        self._to_image = target_img_entity_id
        self._from_image = 0 if self._to_image == 1 else 1
        self._images = dict()
        self._timeout = timeout_delay
        self.reactor = clock if clock is not None else reactor
        self._retry = OmciSoftwareImageActivateSTM.OMCI_SWIMG_ACTIVATE_RETRY_MAX
        self._deferred = None
        self.ret_deferred = None
        self.machine = Machine(model=self, 
                               states=states,
                               transitions=transitions,
                               initial='starting',
                               queued=True,
                               name='{}-image_activate_machine'.format(self.__class__.__name__))

    def start(self):
        print("Start switch software image to " + str(self._to_image))
        self._images[0] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 0, ["is_active", "is_committed", "is_valid"])
        self._images[1] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 1, ["is_active", "is_committed", "is_valid"])
        # print(self._images[self._to_image])
        # print(str(self._images[self._to_image]["is_active"]))
        # print(str(self._images[self._to_image]["is_valid"]))
        if (self._images[self._to_image]["is_active"] == 0 and self._images[self._to_image]["is_valid"] == 1):
            self.reactor.callLater(0, self.activate)
        self.ret_deferred = defer.Deferred()
        return self.ret_deferred

    def __activte_success(self, rx_frame):
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._to_image, 	{"is_active": 1})
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._from_image, {"is_active": 0})
        self.reboot()

    def __activate_fail(self, fail):
        pass
        
    def __commit_success(self, rx_frame):
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._to_image, {"is_committed": 1})
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._from_image, {"is_committed": 0})
        self.commit_ok()

    def __commit_fail(self, fail):
        pass

    def on_enter_starting(self):
        print("on_enter_starting")
        self._images[0] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 0, ["is_active", "is_committed", "is_valid"])
        self._images[1] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 1, ["is_active", "is_committed", "is_valid"])
        if (self._images[self._to_image]["is_active"] != 1 and self._images[self._to_image]["is_valid"] == 1):
            self.activate()
            
    def on_enter_activating(self):
        print("on_enter_activating")
        self._deferred = self._device.omci_cc.send_active_image(self._to_image)
        self._deferred.addCallbacks(self.__activte_success, self.__activate_fail)

    def on_enter_rebooting(self):
        print("on_enter_rebooting")
        
    def on_enter_committing(self):
        print("on_enter_committing")
        img = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, self._to_image, 
                                            ["is_active", "is_committed", "is_valid"])
        if (img['is_active'] != 1):
            self.reset()
        else:
            self._deferred = self._device.omci_cc.send_commit_image(self._to_image)
            self._deferred.addCallbacks(self.__commit_success, self.__commit_fail)

    def on_enter_done(self):
        print("on_enter_done")
        self.ret_deferred.callback(self._to_image)

    def on_enter_failed(self):
        print("on_enter_failed")
        self.ret_deferred.errback(failure.Failure(Exception('ONU Software Activating Failed, instance ' + str(self._to_image))))

###################################################################################
##              Image Agent for OLT/ONT software image handling
###################################################################################
class ImageAgent(object):
    """
        Image Agent supports multiple state machines running at the same time:
    """
    # def __init__(self, omci_agent, dev_id, stm_cls, img_tasks, advertise_events=True):
    def __init__(self, omci_agent, dev_id, dwld_stm_cls, dwld_img_tasks, upgrade_onu_stm_cls, 
                     image_activate_stm_cls, advertise_events=True, clock=None):
        """
        Class initialization

        :param omci_agent: (OpenOmciAgent) Agent
        :param dev_id    : (str) ONU Device ID
        :param dwld_stm_cls          : (ImageDownloadeSTM) Image download state machine class
        :param dwld_img_tasks        : (FileDownloadTask) file download task
        :param upgrade_onu_stm_cls   : (OmciSoftwareImageDownloadSTM) ONU Image upgrade state machine class
        """
        
        self.log = structlog.get_logger(device_id=dev_id)

        self._omci_agent = omci_agent
        self._device_id = dev_id
        self._dwld_stm_cls  = dwld_stm_cls
        self._download_task = dwld_img_tasks['download-file'] 
        self._advertise_events = advertise_events
        self._images = dict()
        self._omci_upgrade_sm_cls = upgrade_onu_stm_cls
        self._omci_upgrade_sm = None
        self._omci_activate_img_sm_cls = image_activate_stm_cls
        self._omci_activate_img_sm = None
        self.reactor = clock if clock is not None else reactor
        
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
            self._images[name] = self._dwld_stm_cls(self._omci_agent, self._device_id, name, 
                                                    local_dir, remote_url, self._download_task,
                                                    timeout_delay=timeout_delay)
        elif self._images[name].download_state != ImageDownload.DOWNLOAD_SUCCEEDED:
            self._images[name].reset()
            
        d = self._images[name].get_file()
        # reactor.callLater(0, self._images[name].start)
        return d

    def __get_standby_instance(self):
        instance_id = None
        instance_0 = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 0, ["is_active", "is_committed"])
        if instance_0['is_active'] == 1:
            instance_id = 1
        else:
            instance_1 = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 1, ["is_active", "is_committed"])
            if instance_1['is_active'] == 1:
                instance_id = 0
        return instance_id

    def upgrade_onu(self, image_name):
        """
        Start upgrading ONU.
        : Return Defer instance to get called after upgrading success or failed. 
        : Or return None if in progress
        """
        print("image_agent.upgrade_onu")
        if self._omci_upgrade_sm is None:
            self._omci_upgrade_sm = self._omci_upgrade_sm_cls(self._omci_agent, self._device_id, clock=self.reactor)
            self._omci_upgrade_sm.instance_id = self.__get_standby_instance()
            self._omci_upgrade_sm.image_filename = image_name
            return self._omci_upgrade_sm.start()
        else:
            return None

    def switch_onu_image(self):
        if self._omci_activate_img_sm is None:
            self._omci_activate_img_sm = self._omci_activate_img_sm_cls(self._omci_agent, self._device_id, 
                                                                        self.__get_standby_instance(), clock=self.reactor)
            return self._omci_activate_img_sm.start()
        else:
            return None
            
    def onu_bootup(self):
        print("ONU Boot Up ...");
        if self._omci_activate_img_sm is not None:
            self._omci_activate_img_sm.bootup()
    
