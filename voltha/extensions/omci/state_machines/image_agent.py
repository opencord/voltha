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
from binascii import crc32, hexlify
from transitions import Machine
from transitions.extensions.nesting import HierarchicalMachine as HMachine
from twisted.python import failure
from twisted.internet import reactor
from twisted.internet.defer import Deferred, CancelledError
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

    # def __init__(self, omci_agent, dev_id, local_name, local_dir, remote_url, download_task, 
    def __init__(self, omci_agent, image_download, 
                     download_task_cls, 
                     states=DEFAULT_STATES,
                     transitions=DEFAULT_TRANSITIONS,
                     initial_state='disabled',
                     timeout_delay=DEFAULT_TIMEOUT_RETRY,
                     advertise_events=True, clock=None):
        """
        :Param: omci_agent:	(OpenOMCIAgent)
        :Param: image_dnld: (ImageDownload)
                            ImageDownload.id  : device id
                            ImageDownload.name: file name of the image 
                            ImageDownload.url : URL to download the image from server
                            ImageDownload.local_dir: local directory of the image file
        """
        self.log = structlog.get_logger(device_id=image_download.id)
        self._agent = omci_agent
        # self._imgdw = ImageDownload()
        # self._imgdw.name = local_name
        # self._imgdw.id   = dev_id
        # self._imgdw.url  = remote_url
        # self._imgdw.local_dir = local_dir
        self._imgdw = image_download
        self._imgdw.state = ImageDownload.DOWNLOAD_UNKNOWN   # voltha_pb2

        self._download_task_cls = download_task_cls
        self._timeout_delay   = timeout_delay

        self._current_task  = None
        self._task_deferred = None
        self._ret_deferred  = None
        self._timeout_dc = None    # DelayedCall
        self._advertise_events = advertise_events
        self.reactor = clock if clock is not None else reactor 

        self.log.debug("ImageDownloadeSTM", image_download=self._imgdw)
        self.machine = Machine(model=self, states=states,
                               transitions=transitions,
                               initial=initial_state,
                               queued=True,
                               name='{}-{}'.format(self.__class__.__name__, self._imgdw.id))
    # @property
    # def name(self):
    #     return self._imgdw.name

    def _cancel_timeout(self):
        d, self._timeout_dc = self._timeout_dc, None
        if d is not None and not d.called:
            d.cancel()

    @property
    def download_status(self):
        return self._imgdw

    def advertise(self, event, info):
        """Advertise an event on the OpenOMCI event bus"""
        if self._advertise_events:
            self._agent.advertise(event,
                                  {
                                      'state-machine': self.machine.name,
                                      'info': info,
                                      'time': str(datetime.utcnow())
                                  })

    # def reset(self):
    #     """
    #     Reset all the state machine to intial state
    #     It is used to clear failed result in last downloading
    #     """
    #     self.log.debug('ImageAgent: reset download', image_download=self._imgdw)
    #     if self._current_task is not None:
    #         self._current_task.stop()
            
    #     self._cancel_deferred()
        
    #     if self._ret_deferred is not None:
    #         self._ret_deferred.cancel()
    #         self._ret_deferred = None

    #     self.stop()
    #     self._imgdw.state = ImageDownload.DOWNLOAD_UNKNOWN
        
    def get_file(self):
        """
          return a Deferred object
          Caller will register a callback to the Deferred to get notified once the image is available
        """
        # self.log.debug('get_file', image_download=self._imgdw)
        if self._ret_deferred is None or self._ret_deferred.called:
            self._ret_deferred = Deferred()
            
        if self._imgdw.state == ImageDownload.DOWNLOAD_SUCCEEDED:
            self.log.debug('ImageAgent: Image Available')
            self.reactor.callLater(0, self._ret_deferred.callback, self._imgdw)
        elif self._imgdw.state == ImageDownload.DOWNLOAD_FAILED or self._imgdw.state == ImageDownload.DOWNLOAD_UNSUPPORTED:
            self.log.debug('ImageAgent: Image not exist')
            self.reactor.callLater(0, self._ret_deferred.errback, failure.Failure(Exception('Image Download Failed ' + self._imgdw.name)))
        elif self._imgdw.state == ImageDownload.DOWNLOAD_UNKNOWN:
            self.log.debug('ImageAgent: Start Image STM')
            self._imgdw.state = ImageDownload.DOWNLOAD_STARTED
            self.reactor.callLater(0, self.start)
        else:
            self.log.debug('ImageAgent: NO action', state=self._imgdw.state)
            
        return self._ret_deferred
            
    def timeout(self):
        self.log.debug('ImageAgent: Image Download Timeout', download_task=self._current_task);
        if self._current_task:
            self.reactor.callLater(0, self.current_task.stop)
        # if self._task_deferred is not None and not self._task_deferred.called:
        #     self._task_deferred.cancel()
            self._current_task = None
        # else:
        #     self.dw_fail()
            
    def on_enter_downloading(self):
        self.log.debug("ImageAgent: on_enter_downloading")
        self.advertise(OpenOmciEventType.state_change, self.state)
        def success(results):
            self.log.debug('ImageAgent: image-download-success', results=results)
            self._imgdw.state = ImageDownload.DOWNLOAD_SUCCEEDED
            self._imgdw.reason = ImageDownload.NO_ERROR
            self._current_task = None
            self._task_deferred = None
            self.dw_success()

        def failure(reason):
            self.log.info('ImageAgent: image-download-failure', reason=reason)
            if self._imgdw.state == ImageDownload.DOWNLOAD_STARTED:
                self._imgdw.state = ImageDownload.DOWNLOAD_FAILED
            if isinstance(reason, CancelledError): 
                self._imgdw.reason = ImageDownload.CANCELLED
            self._current_task = None
            self._task_deferred = None
            self.dw_fail()

        self._device = self._agent.get_device(self._imgdw.id)
        self._current_task = self._download_task_cls(self._agent, self._imgdw)

        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)
        self._imgdw.state = ImageDownload.DOWNLOAD_STARTED

        if self._timeout_delay > 0:
            self._timeout_dc = self.reactor.callLater(self._timeout_delay, self.timeout)

    def on_enter_validating(self):
        self.log.debug("ImageAgent: on_enter_validating")
        self.advertise(OpenOmciEventType.state_change, self.state)
        self.validate_success()

    def on_enter_done(self):
        self.log.debug("ImageAgent: on_enter_done")
        self.advertise(OpenOmciEventType.state_change, self.state)
        self._cancel_timeout()

        d, self._ret_deferred = self._ret_deferred, None
        if d is not None:
            if self._imgdw.state == ImageDownload.DOWNLOAD_SUCCEEDED:
                self.reactor.callLater(0, d.callback, self._imgdw)
            else:  # failed
                if self._imgdw.reason == ImageDownload.CANCELLED:
                    self.reactor.callLater(0, d.cancel)
                else:
                    self.reactor.callLater(0, d.errback, failure.Failure(Exception('Image Download Failed ' + self._imgdw.name)))
            
    def on_enter_disabled(self):
        self.log.debug("ImageAgent: on_enter_disabled")
        self.advertise(OpenOmciEventType.state_change, self.state)

        self._cancel_timeout()
        if self._current_task is not None:
            self.reactor.callLater(0, self._current_task.stop)
            self._current_task = None

        if self._ret_deferred:
            self.reactor.callLater(0, self._ret_deferred.cancel)
            self._ret_deferred = None
            
        # remove local file fragments if download failed
        file_path = self._imgdw.local_dir + '/' + self._imgdw.name
        if self._imgdw.state != ImageDownload.DOWNLOAD_SUCCEEDED and os.path.exists(file_path):
            os.remove(file_path)            
        self._imgdw.state = ImageDownload.DOWNLOAD_UNKNOWN

###################################################################################
##              OMCI Software Image Download Procedure
###################################################################################

class OmciSoftwareImageDownloadSTM(object):
    
    OMCI_SWIMG_DOWNLOAD_TIMEOUT = 1800      # Seconds for the full downloading procedure to avoid errors that cause infinte downloading
    OMCI_SWIMG_DOWNLOAD_WINDOW_SIZE = 32
    OMCI_SWIMG_WINDOW_RETRY_MAX = 2

    # def __init__(self, omci_agent, dev_id, img_path, 
    def __init__(self, image_id, omci_agent, image_dnld,
                     window_size=OMCI_SWIMG_DOWNLOAD_WINDOW_SIZE,
                     timeout_delay=OMCI_SWIMG_DOWNLOAD_TIMEOUT,
                     advertise_events=True,
                     clock=None):
        """
        omci_agent:	(OpenOMCIAgent)
        image_dnld: (ImageDownload)
                    ImageDownload.id  : device id
                    ImageDownload.name: file name of the image 
                    ImageDownload.url : URL to download the image from server
                    ImageDownload.local_dir: local directory of the image file
        window_size: window size of OMCI download procedure 
        """
        self.log = structlog.get_logger(device_id=image_dnld.id)
        self._omci_agent = omci_agent
        self._image_download = image_dnld
        self._timeout = timeout_delay
        self._window_size = window_size
        self.reactor = clock if clock is not None else reactor
        self._offset = 0
        # self._win_section = 0
        self._win_retry   = 0
        self._device = omci_agent.get_device(image_dnld.id)
        self.__init_state_machine()
        self._ret_deferred = None
        self._image_id = image_id
        self._image_file = image_dnld.local_dir + '/' + image_dnld.name
        self._image_obj = open(self._image_file, mode='rb')
        self._image_size = os.path.getsize(self._image_file)
        self._crc32 = 0
        self._win_crc32 = 0
        self._win_data = None
        self._current_deferred = None
        self._result = None    # ReasonCodes
        self.crctable = []
        self._crctable_init = False
        self.log.debug("DownloadSTM", image=self._image_file, image_size=self._image_size)
 
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
            {'trigger': 'download_window',  'source': 'starting_image', 'dest': 'dwin_init_window' },
            {'trigger': 'download_success', 'source': 'dwin',           'dest': 'ending_image'   },
            {'trigger': 'end_img_success',  'source': 'ending_image',   'dest': 'done_image'     },
            # {'trigger': 'download_fail',    'source': 'dwin',           'dest': 'done_image'     },
            # {'trigger': 'end_img_fail',     'source': 'ending_image',   'dest': 'done_image'     },
            {'trigger': 'download_fail',    'source': ['starting_image',  'dwin', 'ending_image'], 'dest': 'done_image'},
            {'trigger': 'reset_image',      'source': '*',              'dest': 'init_image'     },
        ]
        
        self.img_machine = HMachine(model=self, 
                                   states=OMCI_SWIMG_DOWNLOAD_STATES,
                                   transitions=OMCI_SWIMG_DOWNLOAD_TRANSITIONS,
                                   initial='init_image',
                                   queued=True,
                                   name='{}-image_download_machine'.format(self.__class__.__name__))

    # @property
    # def image_filename(self):
    #     return self._image_file

    # @image_filename.setter
    # def image_filename(self, value):
    #     if self._image_fd is not None:
    #         self._image_fd.close()
    #     self._image_filename = value
    #     self._image_fd = open(self._image_filename, mode='rb')
    #     self._image_size = os.path.getsize(self._image_filename)
    #    print("Set image file: " + self._image_filename + " size: " + str(self._image_size))

    def __omci_resp_success(self, rx_frame, cur_state):
        # self.log.debug("ImageAgent: __omci_resp_success: ", current_state=cur_state)
        if cur_state == 'starting_image':
            self.download_window()
        elif cur_state == 'ending_image':
            self._result = ReasonCodes.Success
            self.end_img_success()
        return rx_frame

    def __omci_resp_fail(self, fail, cur_state):
        self.log.debug("ImageAgent: __omci_resp_fail: ", current_state=cur_state)
        if cur_state == 'starting_image':
            self._result = ReasonCodes.ProcessingError
            self.download_fail()
        elif cur_state == 'ending_image':
            self._result = ReasonCodes.ProcessingError
            self.download_fail()

    def __omci_send_window_resp_success(self, rx_frame, cur_state, datasize):
        # self.log.debug("ImageAgent: __omci_send_window_resp_success", current_state=cur_state)
        self._offset += datasize
        self._image_download.downloaded_bytes += datasize
        self.rx_ack_success()

    def __omci_send_window_resp_fail(self, fail, cur_state):
        self.log.debug("ImageAgent: __omci_send_window_resp_fail", current_state=cur_state)
        self.rx_ack_failed()

#    @property
#    def image_id(self):
#        return self._image_id

#    @image_id.setter
#    def image_id(self, value):
#        self._image_id = value

    def start(self):
        self.log.debug("ImageAgent: OmciSoftwareImageDownloadSTM.start", current_state=self.state)
        if self._ret_deferred is None:
            self._ret_deferred = Deferred()
        if self.state == 'init_image':
            self.reactor.callLater(0, self.start_image)
        return self._ret_deferred

    def stop(self):
        self.log.debug("ImageAgent: OmciSoftwareImageDownloadSTM.stop", current_state=self.state)
        self._result = ReasonCodes.OperationCancelled
        self.download_fail()
        
    def on_enter_init_image(self):
        self.log.debug("ImageAgent: on_enter_init_image")
        self._image_obj.seek(0)
        self._offset = 0
        # self._win_section = 0
        self._win_retry   = 0
        
    def on_enter_starting_image(self):
        self.log.debug("ImageAgent: on_enter_starting_image")
        self._image_download.downloaded_bytes = 0
        self._current_deferred = self._device.omci_cc.send_start_software_download(self._image_id, self._image_size, self._window_size)
        self._current_deferred.addCallbacks(self.__omci_resp_success, self.__omci_resp_fail,
                                            callbackArgs=(self.state,), errbackArgs=(self.state,))

    def on_enter_dwin_init_window(self):
        self.log.debug("ImageAgent: on_enter_dwin_init_window", offset=self._offset, image_size=self._image_size)
        if self._offset < self._image_size:
            self.send_sections()

    def on_enter_dwin_sending_sections(self):
        # self.log.debug("ImageAgent: on_enter_dwin_sending_sections", offset=self._offset)

        if (self._offset + self._window_size * OmciSectionDataSize) <= self._image_size:
            sections = self._window_size
            mod = 0
            datasize = self._window_size * OmciSectionDataSize
        else:
            datasize = self._image_size - self._offset
            sections = datasize / OmciSectionDataSize
            mod = datasize % OmciSectionDataSize
            sections = sections + 1 if mod > 0 else sections

        self.log.debug("ImageAgent: on_enter_dwin_sending_sections", offset=self._offset, datasize=datasize, sections=sections)
        if self._win_retry == 0:
            self._win_data = self._image_obj.read(datasize)
            self._win_crc32 = self.crc32(self._crc32, self._win_data)
            # self.log.debug("CRC32", crc32=self._win_crc32, offset=self._offset)
        else:
            self.log.debug("Retry download window with crc32", offset=self._offset)
            
        sent = 0
        for i in range(0, sections):
            if i < sections - 1:
                # self.log.debug("section data", data=hexlify(data[(self._offset+sent):(self._offset+sent+OmciSectionDataSize)]))
                self._device.omci_cc.send_download_section(self._image_id, i,
                                                           self._win_data[sent:sent+OmciSectionDataSize])
                sent += OmciSectionDataSize
            else:
                last_size = OmciSectionDataSize if mod == 0 else mod
                self._current_deferred = self._device.omci_cc.send_download_section(self._image_id, i,
                                                           self._win_data[sent:sent+last_size],
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
        self.log.debug("ImageAgent: on_enter_dwin_window_success")
        self._crc32 = self._win_crc32 if self._win_crc32 != 0 else self._crc32
        self._win_crc32 = 0
        self._win_retry = 0
        if self._offset < self._image_size:
            self.reset_window()
        else:
            self.download_success()

    def on_enter_dwin_window_failed(self):
        self.log.debug("ImageAgent: on_enter_dwin_window_fail: ", retry=self._win_retry)
        if self._win_retry < self.OMCI_SWIMG_WINDOW_RETRY_MAX:
            self._win_retry += 1
            self.reset_window()
        else:
            self._result = ReasonCodes.ProcessingError
            self.download_fail()

    def on_enter_ending_image(self):
        self.log.debug("ImageAgent: on_enter_ending_image", crc32=self._crc32)
        self._current_deferred = self._device.omci_cc.send_end_software_download(self._image_id, self._crc32, self._image_size)
        self._current_deferred.addCallbacks(self.__omci_resp_success, self.__omci_resp_fail,
                                            callbackArgs=(self.state,), errbackArgs=(self.state,))

    def on_enter_done_image(self):
        self.log.debug("ImageAgent: on_enter_done_image", result=self._result)
        if self._result == ReasonCodes.Success:
            self.reactor.callLater(0, self._ret_deferred.callback, self._image_download) # (str(self._instance_id))
        else:
            self._ret_deferred.errback(failure.Failure(Exception('ONU Software Download Failed, instance ' + str(self._image_id))))

    def __crc_GenTable32(self):
        if self._crctable_init:
            return
            
        #  x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1   
        pn32 = [0, 1, 2, 4, 5, 7, 8, 10, 11, 12, 16, 22, 23, 26]
        poly = 0
        for i in pn32:
            poly |= (1 << i)

        for i in range(0, 256):
            _accum = (i << 24) & 0xFFFFFFFF
            for j in range(0, 8):
                if _accum & (1 << 31):
                    _accum = (_accum << 1) ^ poly
                else:
                    _accum = (_accum << 1) & 0xFFFFFFFF
            # self.crctable[i] = accum
            self.crctable.append(_accum)
        self._crctable_init = True
            
    def crc32(self, accum, data):
        self.__crc_GenTable32()
        _accum = ~accum & 0xFFFFFFFF
        num = len(data)
        for i in range(0, num):
            _accum = self.crctable[((_accum >> 24) ^ ord(data[i])) & 0xFF] ^ ((_accum << 8) & 0xFFFFFFFF)

        return ~_accum & 0xFFFFFFFF

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
        self.log = structlog.get_logger(device_id=dev_id)
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
        self.log.debug("OmciSoftwareImageActivateSTM", target=self._to_image)

    def __activte_success(self, rx_frame):
        self.log.debug("Activate software image success, rebooting ONU ...", device_id=self._device_id)
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._to_image, 	{"is_active": 1})
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._from_image, {"is_active": 0})
        self.reboot()

    def __activate_fail(self, fail):
        self.log.debug("Activate software image failed", faile=fail)
        
    def __commit_success(self, rx_frame):
        self.log.debug("Commit software success", device_id=self._device_id)
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._to_image, {"is_committed": 1})
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._from_image, {"is_committed": 0})
        self.commit_ok()

    def __commit_fail(self, fail):
        self.log.debug("Commit software image failed", faile=fail)
        
    def start(self):
        self.log.debug("Start switch software image", target=self._to_image)
        self._images[0] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 0, ["is_active", "is_committed", "is_valid"])
        self._images[1] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 1, ["is_active", "is_committed", "is_valid"])
        # print(self._images[self._to_image])
        # print(str(self._images[self._to_image]["is_active"]))
        # print(str(self._images[self._to_image]["is_valid"]))
        if (self._images[self._to_image]["is_active"] == 0 and self._images[self._to_image]["is_valid"] == 1):
            self.reactor.callLater(0, self.activate)
        self.ret_deferred = Deferred()
        return self.ret_deferred

    def on_enter_starting(self):
        self.log.debug("on_enter_starting")
        self._images[0] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 0, ["is_active", "is_committed", "is_valid"])
        self._images[1] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 1, ["is_active", "is_committed", "is_valid"])
        if (self._images[self._to_image]["is_active"] != 1 and self._images[self._to_image]["is_valid"] == 1):
            self.activate()
            
    def on_enter_activating(self):
        self.log.debug("on_enter_activating")
        self._deferred = self._device.omci_cc.send_active_image(self._to_image)
        self._deferred.addCallbacks(self.__activte_success, self.__activate_fail)

    def on_enter_rebooting(self):
        self.log.debug("on_enter_rebooting")
        
    def on_enter_committing(self):
        self.log.debug("on_enter_committing")
        img = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, self._to_image, 
                                            ["is_active", "is_committed", "is_valid"])
        if (img['is_active'] != 1):
            self.reset()
        else:
            self._deferred = self._device.omci_cc.send_commit_image(self._to_image)
            self._deferred.addCallbacks(self.__commit_success, self.__commit_fail)

    def on_enter_done(self):
        self.log.debug("on_enter_done")
        self.ret_deferred.callback(self._to_image)

    def on_enter_failed(self):
        self.log.debug("on_enter_failed")
        self.ret_deferred.errback(failure.Failure(Exception('ONU Software Activating Failed, instance ' + str(self._to_image))))

###################################################################################
##              Image Agent for OLT/ONT software image handling
###################################################################################
class ImageAgent(object):
    """
        Image Agent supports multiple state machines running at the same time:
    """

    DEFAULT_LOCAL_ROOT = "/"
    
    # def __init__(self, omci_agent, dev_id, stm_cls, img_tasks, advertise_events=True):
    def __init__(self, omci_agent, dev_id, 
                     dwld_stm_cls, dwld_img_tasks, 
                     upgrade_onu_stm_cls, upgrade_onu_tasks, 
                     image_activate_stm_cls, 
                     advertise_events=True, local_dir=None, clock=None):
        """
        Class initialization

        :param omci_agent: (OpenOmciAgent) Agent
        :param dev_id    : (str) ONU Device ID
        :param dwld_stm_cls          : (ImageDownloadeSTM) Image download state machine class
        :param dwld_img_tasks        : (FileDownloadTask) file download task
        :param upgrade_onu_stm_cls   : (OmciSoftwareImageDownloadSTM) ONU Image upgrade state machine class
        :param upgrade_onu_tasks     : ({OmciSwImageUpgradeTask})
        :param image_activate_stm_cls: (OmciSoftwareImageActivateSTM)
        """
        
        self.log = structlog.get_logger(device_id=dev_id)

        self._omci_agent = omci_agent
        self._device_id = dev_id
        self._dwld_stm_cls  = dwld_stm_cls
        self._image_download_sm = None
        self._download_task_cls = dwld_img_tasks['download-file'] 

        self._omci_upgrade_sm_cls = upgrade_onu_stm_cls
        self._omci_upgrade_task_cls = upgrade_onu_tasks['omci_upgrade_task']
        self._omci_upgrade_task = None
        self._omci_upgrade_defer = None
        
        self._omci_activate_img_sm_cls = image_activate_stm_cls
        self._omci_activate_img_sm = None
        self.reactor = clock if clock is not None else reactor

        self._advertise_events = advertise_events
        self._local_dir = None

        self._device = None
        # onu_dev = self._omci_agent.get_device(self._device_id)
        # assert device
        
        # self._local_dir = DEFAULT_LOCAL_ROOT + onu_dev.adapter_agent.name
        # self.log.debug("ImageAgent", local_dir=self._local_dir)
        
        
    def __get_standby_image(self):
        instance_id = None
        instance_0 = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 0, ["is_active", "is_committed"])
        if instance_0['is_active'] == 1:
            instance_id = 1
        else:
            instance_1 = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 1, ["is_active", "is_committed"])
            if instance_1['is_active'] == 1:
                instance_id = 0
        return instance_id

    # def get_image(self, name, local_dir, remote_url, timeout_delay=ImageDownloadeSTM.DEFAULT_TIMEOUT_RETRY):
    def get_image(self, image_download, timeout_delay=ImageDownloadeSTM.DEFAULT_TIMEOUT_RETRY):

        """
         Get named image from servers
        :param image_download: (voltha_pb2.ImageDownload)
        :param timeout_delay : (number) timeout for download task
        :
        :Return a Deferred that will be triggered if the file is locally availabe or downloaded sucessfully
        :  Caller will register callback and errback to the returned defer to get notified
        """
        self.log.debug("ImageAgent: get_image")

        if self._local_dir is None:
            onu_dev = self._omci_agent.get_device(self._device_id)
            assert onu_dev
            if image_download.local_dir is None:
                self._local_dir = ImageAgent.DEFAULT_LOCAL_ROOT + onu_dev.adapter_agent.name
            else:
                self._local_dir = image_download.local_dir + '/' + onu_dev.adapter_agent.name
            
            # self.log.debug("ImageAgent", local_dir=self._local_dir)
            image_download.local_dir = self._local_dir
            
        if os.path.isfile(self._local_dir + '/' + image_download.name): # image file exists
            d = Deferred()
            self.reactor.callLater(0, d.callback, image_download)
            self.log.debug("ImageAgent: Image file exists")
            return d
            
        if self._image_download_sm is None:
            self._image_download_sm = self._dwld_stm_cls(self._omci_agent, # self._device_id, name, local_dir, remote_url, 
                                                         image_download,
                                                         self._download_task_cls,
                                                         timeout_delay=timeout_delay,
                                                         clock=self.reactor
                                                        )
        else:
            if self._image_download_sm.download_status.state != ImageDownload.DOWNLOAD_SUCCEEDED:
                self._image_download_sm.reset()
            
        d = self._image_download_sm.get_file()
        # reactor.callLater(0, self._images[name].start)
        return d

    def cancel_download_image(self):
        if self._image_download_sm is not None:
            self._image_download_sm.stop()
            self._image_download_sm = None
            
            
    def upgrade_onu(self, image_dnld, restart=False):
        """
        Start upgrading ONU.
        image_dnld: (ImageDownload)
        : Return Defer instance to get called after upgrading success or failed. 
        : Or return None if in progress
        """
        self.log.debug("ImageAgent: upgrade_onu", image_download=image_dnld)

        self._device = self._omci_agent.get_device(image_dnld.id) if self._device is None else self._device

        if restart:
            self.cancel_upgrade_onu()            
            
        if self._omci_upgrade_task is None:
            img_id = self.__get_standby_image()
            self.log.debug("ImageAgent: start task", image_Id=img_id, task=self._omci_upgrade_sm_cls)
            self._omci_upgrade_task = self._omci_upgrade_task_cls(img_id, 
                                                                  self._omci_upgrade_sm_cls, 
                                                                  self._omci_agent, 
                                                                  image_dnld, clock=self.reactor)
            self.log.debug("ImageAgent: task created but not started")
            self._omci_upgrade_deferred = self._device.task_runner.queue_task(self._omci_upgrade_task)
        return self._omci_upgrade_deferred


    def cancel_upgrade_onu(self):
        self.log.debug("ImageAgent: cancel_upgrade_onu")
        if self._omci_upgrade_task is not None:
            if self._omci_upgrade_task.running:
                self._omci_upgrade_task.stop()
            self._omci_upgrade_task = None
        if self._omci_upgrade_deferred is not None:
           self.reactor.callLater(0, self._omci_upgrade_deferred.cancel)
           self._omci_upgrade_deferred = None
           

    def switch_onu_image(self):
        self.log.debug("ImageAgent: switch_onu_image")
        if self._omci_activate_img_sm is None:
            self._omci_activate_img_sm = self._omci_activate_img_sm_cls(self._omci_agent, self._device_id, 
                                                                        self.__get_standby_instance(), clock=self.reactor)
            return self._omci_activate_img_sm.start()
        else:
            return None
            
    def onu_bootup(self):
        self.log.debug("ImageAgent: ONU Boot Up ...");
        if self._omci_activate_img_sm is not None:
            self._omci_activate_img_sm.bootup()

