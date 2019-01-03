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
from voltha.extensions.omci.omci_messages import OmciEndSoftwareDownloadResponse, OmciActivateImageResponse

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
    DEFAULT_TIMEOUT_RETRY = 1000      # Seconds to delay after task failure/timeout

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
        # self._imgdw.state = ImageDownload.DOWNLOAD_UNKNOWN   # voltha_pb2

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
    def status(self):
        return self._imgdw

    @property
    def deferred(self):
        return self._ret_deferred
        
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
    #     self.log.debug('reset download', image_download=self._imgdw)
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
            self.log.debug('Image Available')
            self.reactor.callLater(0, self._ret_deferred.callback, self._imgdw)
        elif self._imgdw.state == ImageDownload.DOWNLOAD_FAILED or self._imgdw.state == ImageDownload.DOWNLOAD_UNSUPPORTED:
            self.log.debug('Image not exist')
            self.reactor.callLater(0, self._ret_deferred.errback, failure.Failure(Exception('Image Download Failed ' + self._imgdw.name)))
        elif self._imgdw.state == ImageDownload.DOWNLOAD_UNKNOWN or self._imgdw.state == ImageDownload.DOWNLOAD_REQUESTED:
            self.log.debug('Start Image STM')
            self._imgdw.state = ImageDownload.DOWNLOAD_STARTED
            self.reactor.callLater(0, self.start)
        else:
            self.log.debug('NO action', state=self._imgdw.state)
            
        return self._ret_deferred
            
    def timeout(self):
        self.log.debug('Image Download Timeout', download_task=self._current_task);
        if self._current_task:
            self.reactor.callLater(0, self._current_task.stop)
        # if self._task_deferred is not None and not self._task_deferred.called:
        #     self._task_deferred.cancel()
            self._current_task = None
        # else:
        #     self.dw_fail()
            
    def on_enter_downloading(self):
        self.log.debug("on_enter_downloading")
        self.advertise(OpenOmciEventType.state_change, self.state)
        def success(results):
            self.log.debug('image-download-success', results=results)
            self._imgdw.state = ImageDownload.DOWNLOAD_SUCCEEDED
            self._imgdw.reason = ImageDownload.NO_ERROR
            self._current_task = None
            self._task_deferred = None
            self.dw_success()

        def failure(reason):
            self.log.info('image-download-failure', reason=reason)
            if self._imgdw.state == ImageDownload.DOWNLOAD_STARTED:
                self._imgdw.state = ImageDownload.DOWNLOAD_FAILED
            if isinstance(reason, CancelledError): 
                self._imgdw.reason = ImageDownload.CANCELLED
            self._current_task = None
            self._task_deferred = None
            self.dw_fail()

        self._device = self._agent.get_device(self._imgdw.id)
        self._current_task = self._download_task_cls(self._agent, self._imgdw, self.reactor)

        self._task_deferred = self._device.task_runner.queue_task(self._current_task)
        self._task_deferred.addCallbacks(success, failure)
        self._imgdw.state = ImageDownload.DOWNLOAD_STARTED

        if self._timeout_delay > 0:
            self._timeout_dc = self.reactor.callLater(self._timeout_delay, self.timeout)

    def on_enter_validating(self):
        self.log.debug("on_enter_validating")
        self.advertise(OpenOmciEventType.state_change, self.state)
        self.validate_success()

    def on_enter_done(self):
        self.log.debug("on_enter_done")
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
        self.log.debug("on_enter_disabled")
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
    
    OMCI_SWIMG_DOWNLOAD_TIMEOUT = 5400      # TODO: Seconds for the full downloading procedure to avoid errors that cause infinte downloading
    OMCI_SWIMG_DOWNLOAD_WINDOW_SIZE = 32
    OMCI_SWIMG_WINDOW_RETRY_MAX = 2
    OMCI_SWIMG_ACTIVATE_RETRY_MAX = 2
    OMCI_SWIMG_ACTIVATE_TRANSITIONS_TIMEOUT = 10      # Seconds to delay after task failure/timeout

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
        self._timeout_dc = None
        self._window_size = window_size
        self.reactor = clock if clock is not None else reactor
        self._offset = 0
        # self._win_section = 0
        self._win_retry = 0
        self._device_id = image_dnld.id
        self._device = omci_agent.get_device(image_dnld.id)
        self.__init_state_machine()
        self._ret_deferred = None
        self._image_id = image_id    # Target software image entity ID
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
        self._actimg_retry_max = OmciSoftwareImageDownloadSTM.OMCI_SWIMG_ACTIVATE_RETRY_MAX
        self._actimg_retry = 0
        self.log.debug("DownloadSTM", image=self._image_file, image_size=self._image_size)
 
    def __init_state_machine(self):

        #### Download Window Sub State Machine ####
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

        #### Software Activation Sub State Machine ####
        OMCI_SWIMG_ACTIVATE_STATES = ['init_act', 'activating', 'busy', 'rebooting', 'committing', 'done', 'failed']
        OMCI_SWIMG_ACTIVATE_TRANSITIONS = [
            {'trigger': 'activate', 'source': ['init_act', 'busy'], 'dest': 'activating'},
            {'trigger': 'onu_busy', 'source': 'activating', 'dest': 'busy'},
            {'trigger': 'reboot',   'source': 'activating', 'dest': 'rebooting'},
            {'trigger': 'do_commit', 'source': ['activating', 'rebooting'], 'dest': 'committing'},
            # {'trigger': 'commit_ok', 'source': 'committing', 'dest': 'done'},
            {'trigger': 'reset_actimg', 'source': ['activating', 'rebooting', 'committing', 'failed'], 'dest': 'init_act'},
            # {'trigger': 'actimg_fail', 'source': ['init_act', 'activating', 'rebooting', 'committing'], 'dest': 'failed'}
        ]
        
        self.activate_machine = HMachine(model=self, 
                                         states=OMCI_SWIMG_ACTIVATE_STATES,
                                         transitions=OMCI_SWIMG_ACTIVATE_TRANSITIONS,
                                         initial='init_act',
                                         queued=True,
                                         name='{}-activate_machine'.format(self.__class__.__name__))
                                   
        #### Main State Machine ####
        OMCI_SWIMG_DOWNLOAD_STATES = [ 'init_image', 'starting_image', 'ending_image', 'endimg_busy', 'done_image',
                                      {'name': 'dwin', 'children': self.win_machine}, 
                                      {'name': 'actimg', 'children': self.activate_machine}
                                     ]
        OMCI_SWIMG_DOWNLOAD_TRANSITIONS = [
            {'trigger': 'start_image',      'source': 'init_image',     'dest': 'starting_image' },
            {'trigger': 'download_window',  'source': 'starting_image', 'dest': 'dwin_init_window' },
            {'trigger': 'download_success', 'source': 'dwin',           'dest': 'ending_image'   },
            {'trigger': 'onu_busy',         'source': 'ending_image',   'dest': 'endimg_busy'    },
            {'trigger': 'retry_endimg',     'source': 'endimg_busy',    'dest': 'ending_image'   },
            {'trigger': 'end_img_success',  'source': 'ending_image',   'dest': 'actimg_init_act'  },
            {'trigger': 'activate_done',    'source': 'actimg',         'dest': 'done_image'     },
            {'trigger': 'download_fail',    'source': '*',              'dest': 'done_image'     },
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

    def __omci_start_download_resp_success(self, rx_frame):
        self.log.debug("__omci_download_resp_success")
        self.download_window()
        return rx_frame

    def __omci_start_download_resp_fail(self, fail):
        self.log.debug("__omci_download_resp_fail", failure=fail)
        self._result = ReasonCodes.ProcessingError
        self.download_fail()

    def __omci_end_download_resp_success(self, rx_frame):
        self.log.debug("__omci_end_download_resp_success")
        if rx_frame.fields['message_type'] == OmciEndSoftwareDownloadResponse.message_id: # 0x35
            omci_data = rx_frame.fields['omci_message']
            if omci_data.fields['result'] == 0: 
                self.log.debug('OMCI End Image OK')
                self._result = ReasonCodes.Success
                self.end_img_success()
            elif omci_data.fields['result'] == 6: # Device Busy
                self.log.debug('OMCI End Image Busy')
                self.onu_busy()
            else:
                self.log.debug('OMCI End Image Failed', reason=omci_data.fields['result'])
        else:
            self.log.debug('Receive Unexpected OMCI', message_type=rx_frame.fields['message_type'])

    def __omci_end_download_resp_fail(self, fail):
        self.log.debug("__omci_end_download_resp_fail", failure=fail)
        self._result = ReasonCodes.ProcessingError
        self.download_fail()
    
    def __omci_send_window_resp_success(self, rx_frame, cur_state, datasize):
        # self.log.debug("__omci_send_window_resp_success", current_state=cur_state)
        self._offset += datasize
        self._image_download.downloaded_bytes += datasize
        self.rx_ack_success()

    def __omci_send_window_resp_fail(self, fail, cur_state):
        self.log.debug("__omci_send_window_resp_fail", current_state=cur_state)
        self.rx_ack_failed()

    def __activate_resp_success(self, rx_frame):
        self._current_deferred = None
        if rx_frame.fields['message_type'] == OmciActivateImageResponse.message_id: # 0x36
            omci_data = rx_frame.fields['omci_message']
            if omci_data.fields['result'] == 0:
                self.log.debug("Activate software image success, rebooting ONU ...", device_id=self._device.device_id,
                                state=self._image_download.image_state)
                standby_image_id = 0 if self._image_id else 1
                self._omci_agent.database.set(self._device.device_id, SoftwareImage.class_id, self._image_id, 	{"is_active": 1})
                self._omci_agent.database.set(self._device.device_id, SoftwareImage.class_id, standby_image_id, {"is_active": 0})
                self.reboot()
            elif omci_data.fields['result'] == 6: # Device Busy
                self.log.debug('OMCI Activate Image Busy')
                self.onu_busy()
            else:
                self.log.debug('OMCI Activate Image Failed', reason=omci_data['result'])
        else:
            self.log.debug('Receive Unexpected OMCI', message_type=rx_frame['message_type'])
                
    def __activate_fail(self, fail):
        self.log.debug("Activate software image failed", faile=fail)
        self._current_deferred = None
        self._result = ReasonCodes.ProcessingError
        self.activate_done()
        
    def __commit_success(self, rx_frame):
        self.log.debug("Commit software success", device_id=self._device_id)
        self._current_deferred = None
        standby_image_id = 0 if self._image_id else 1
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._image_id, {"is_committed": 1})
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, standby_image_id, {"is_committed": 0})
        self._image_download.image_state = ImageDownload.IMAGE_ACTIVE
        self._result = ReasonCodes.Success
        self.activate_done()

    def __commit_fail(self, fail):
        self.log.debug("Commit software image failed", faile=fail)
        self._current_deferred = None
        self._result = ReasonCodes.ProcessingError
        self._image_download.image_state = ImageDownload.IMAGE_REVERT
        self.activate_done()

#    @property
#    def image_id(self):
#        return self._image_id

#    @image_id.setter
#    def image_id(self, value):
#        self._image_id = value

    @property
    def status(self):
        return self._image_download

    def start(self):
        self.log.debug("OmciSoftwareImageDownloadSTM.start", current_state=self.state)
        if self._ret_deferred is None:
            self._ret_deferred = Deferred()
        if self.state == 'init_image':
            self.reactor.callLater(0, self.start_image)
        return self._ret_deferred

    def stop(self):
        self.log.debug("OmciSoftwareImageDownloadSTM.stop", current_state=self.state)
        self._result = ReasonCodes.OperationCancelled
        self.download_fail()
        
    def on_enter_init_image(self):
        self.log.debug("on_enter_init_image")
        self._image_obj.seek(0)
        self._offset = 0
        # self._win_section = 0
        self._win_retry   = 0
        
    def on_enter_starting_image(self):
        self.log.debug("on_enter_starting_image")
        self._image_download.downloaded_bytes = 0
        self._current_deferred = self._device.omci_cc.send_start_software_download(self._image_id, self._image_size, self._window_size)
        self._current_deferred.addCallbacks(self.__omci_start_download_resp_success, self.__omci_start_download_resp_fail)
                                            # callbackArgs=(self.state,), errbackArgs=(self.state,))

    def on_enter_dwin_init_window(self):
        # self.log.debug("on_enter_dwin_init_window", offset=self._offset, image_size=self._image_size)
        if self._offset < self._image_size:
            self.send_sections()

    def on_enter_dwin_sending_sections(self):
        # self.log.debug("on_enter_dwin_sending_sections", offset=self._offset)

        if (self._offset + self._window_size * OmciSectionDataSize) <= self._image_size:
            sections = self._window_size
            mod = 0
            datasize = self._window_size * OmciSectionDataSize
        else:
            datasize = self._image_size - self._offset
            sections = datasize / OmciSectionDataSize
            mod = datasize % OmciSectionDataSize
            sections = sections + 1 if mod > 0 else sections

        # self.log.debug("on_enter_dwin_sending_sections", offset=self._offset, datasize=datasize, sections=sections)
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
        # self.log.debug("on_enter_dwin_window_success")
        self._crc32 = self._win_crc32 if self._win_crc32 != 0 else self._crc32
        self._win_crc32 = 0
        self._win_retry = 0
        if self._offset < self._image_size:
            self.reset_window()
        else:
            self.download_success()

    def on_enter_dwin_window_failed(self):
        self.log.debug("on_enter_dwin_window_fail: ", retry=self._win_retry)
        if self._win_retry < self.OMCI_SWIMG_WINDOW_RETRY_MAX:
            self._win_retry += 1
            self.reset_window()
        else:
            self._result = ReasonCodes.ProcessingError
            self.download_fail()

    def on_enter_ending_image(self):
        self.log.debug("on_enter_ending_image", crc32=self._crc32)
        self._current_deferred = self._device.omci_cc.send_end_software_download(self._image_id, self._crc32, 
                                                                                 self._image_size, timeout=18)
        self._current_deferred.addCallbacks(self.__omci_end_download_resp_success, self.__omci_end_download_resp_fail)
                                            # callbackArgs=(self.state,), errbackArgs=(self.state,))

    def on_enter_endimg_busy(self):
        self.log.debug("on_enter_endimg_busy")
        self.reactor.callLater(3, self.retry_endimg)

    def on_enter_actimg_init_act(self):
        self.log.debug("on_enter_actimg_init_act", retry=self._actimg_retry, max_retry=self._actimg_retry_max)
        # self._images[0] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 0, ["is_active", "is_committed", "is_valid"])
        # self._images[1] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 1, ["is_active", "is_committed", "is_valid"])
        # if (self._images[self._to_image]["is_active"] != 1 and self._images[self._to_image]["is_valid"] == 1):
        if self._actimg_retry > self._actimg_retry_max:
            self.log.debug("activate image failed: retry max", retries=self._actimg_retry)
            self._result = ReasonCodes.ProcessingError
            self.activate_done()
        else:
            self._image_download.image_state = ImageDownload.IMAGE_ACTIVATE
            self.activate()
            
    def on_enter_actimg_activating(self):
        self.log.debug("on_enter_actimg_activating")
        img = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 
                                              self._image_id, ["is_active", "is_committed", "is_valid"])
                                              
        self.log.debug("on_enter_actimg_activating", instance=self._image_id, state=img)
        if img["is_active"] == 0:
            #if img["is_valid"] == 1:
            self._current_deferred = self._device.omci_cc.send_active_image(self._image_id)
            self._current_deferred.addCallbacks(self.__activate_resp_success, self.__activate_fail)
            #else:
            #    self.fail()
        else:
            self.do_commit()

    def on_enter_actimg_busy(self):
        self.log.debug("on_enter_actimg_busy")
        self.reactor.callLater(3, self.activate)
        
    def __on_reboot_timeout(self):
        self.log.debug("on_reboot_timeout")
        self._timeout_dc = None
        self._result = ReasonCodes.ProcessingError
        self.activate_done()
        
    def on_enter_actimg_rebooting(self):
        self.log.debug("on_enter_actimg_rebooting")
        if self._timeout_dc == None:
            self._timeout_dc = self.reactor.callLater(self._timeout, self.__on_reboot_timeout)

    def on_exit_actimg_rebooting(self):
        self.log.debug("on_exit_actimg_rebooting", timeout=self._timeout_dc)
        if self._timeout_dc and self._timeout_dc.active:
            self._timeout_dc.cancel()
            self._timeout_dc = None
    
    def on_enter_actimg_committing(self):
        # self.log.debug("on_enter_committing")
        img = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 
                                              self._image_id, ["is_active", "is_committed", "is_valid"])
        self.log.debug("on_enter_actimg_committing", instance=self._image_id, state=img)
        if (img['is_active'] == 0):
            self._actimg_retry += 1
            self.log.debug("do retry", retry=self._actimg_retry)
            self.reset_actimg()
        else:
            self._actimg_retry = 0
            self._current_deferred = self._device.omci_cc.send_commit_image(self._image_id)
            self._current_deferred.addCallbacks(self.__commit_success, self.__commit_fail)

    def on_enter_done_image(self):
        self.log.debug("on_enter_done_image", result=self._result)
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
'''
class OmciSoftwareImageActivateSTM(object):
    OMCI_SWIMG_ACTIVATE_STATES = ['starting', 'activating', 'busy', 'rebooting', 'committing', 'done', 'failed']
    OMCI_SWIMG_ACTIVATE_TRANSITIONS = [
        {'trigger': 'activate', 'source': ['starting', 'busy'], 'dest': 'activating'},
        {'trigger': 'onu_busy', 'source': 'activating', 'dest': 'busy'},
        {'trigger': 'reboot',   'source': 'activating', 'dest': 'rebooting'},
        {'trigger': 'do_commit', 'source': ['activating', 'rebooting'], 'dest': 'committing'},
        {'trigger': 'commit_ok', 'source': 'committing', 'dest': 'done'},
        {'trigger': 'reset',    'source': ['activating', 'rebooting', 'committing', 'failed'], 'dest': 'starting'},
        {'trigger': 'fail',     'source': ['starting', 'activating', 'rebooting', 'committing'], 'dest': 'failed'}
    ]
    OMCI_SWIMG_ACTIVATE_TRANSITIONS_TIMEOUT = 10      # Seconds to delay after task failure/timeout
    OMCI_SWIMG_ACTIVATE_RETRY_MAX           = 2
    def __init__(self, omci_agent, dev_id, target_img_entity_id, image_download,
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
        self._image_download = image_download
        # self._images = dict()
        self._timeout = timeout_delay
        self._timeout_dc = None
        self.reactor = clock if clock is not None else reactor
        self._retry_max = OmciSoftwareImageActivateSTM.OMCI_SWIMG_ACTIVATE_RETRY_MAX
        self._retry = 0
        self._deferred = None
        self.ret_deferred = None
        self.machine = Machine(model=self, 
                               states=states,
                               transitions=transitions,
                               initial='starting',
                               queued=True,
                               name='{}-image_activate_machine'.format(self.__class__.__name__))
        self.log.debug("OmciSoftwareImageActivateSTM", target=self._to_image)

    def __activate_resp_success(self, rx_frame):
        if rx_frame.fields['message_type'] == 0x36:  # (OmciActivateImageResponse)
            omci_data = rx_frame.fields['omci_message']
            if omci_data.fields['result'] == 0:
                self.log.debug("Activate software image success, rebooting ONU ...", device_id=self._device_id) 
                self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._to_image, 	{"is_active": 1})
                self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._from_image, {"is_active": 0})
                self.reboot()
            elif omci_data.fields['result'] == 6: # Device Busy
                self.log.debug('OMCI Activate Image Busy')
                self.onu_busy()
            else:
                self.log.debug('OMCI Activate Image Failed', reason=omci_data['result'])
        else:
            self.log.debug('Receive Unexpected OMCI', message_type=rx_frame['message_type'])
                
    def __activate_fail(self, fail):
        self.log.debug("Activate software image failed", faile=fail)
        
    def __commit_success(self, rx_frame):
        self.log.debug("Commit software success", device_id=self._device_id)
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._to_image, {"is_committed": 1})
        self._omci_agent.database.set(self._device_id, SoftwareImage.class_id, self._from_image, {"is_committed": 0})
        self.commit_ok()

    def __commit_fail(self, fail):
        self.log.debug("Commit software image failed", faile=fail)

    @property
    def status(self):
        return self._image_download
        
    def start(self):
        self.log.debug("Start switch software image", target=self._to_image)
        # self._images[0] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 0, ["is_active", "is_committed", "is_valid"])
        # self._images[1] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 1, ["is_active", "is_committed", "is_valid"])
        # if (self._images[self._to_image]["is_active"] == 0 and self._images[self._to_image]["is_valid"] == 1):
        self.ret_deferred = Deferred()
        self._image_download.image_state = ImageDownload.IMAGE_ACTIVATE
        self.reactor.callLater(0, self.activate)
        return self.ret_deferred

    def on_enter_starting(self):
        # self.log.debug("on_enter_starting")
        # self._images[0] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 0, ["is_active", "is_committed", "is_valid"])
        # self._images[1] = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 1, ["is_active", "is_committed", "is_valid"])
        # if (self._images[self._to_image]["is_active"] != 1 and self._images[self._to_image]["is_valid"] == 1):
        if self._retry > self._retry_max:
            self.log.debug("failed: retry max", retries=self._retry)
            self.fail()
        else:
            self.activate()
            
    def on_enter_activating(self):
        img = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 
                                              self._to_image, ["is_active", "is_committed", "is_valid"])
                                              
        self.log.debug("on_enter_activating", instance=self._to_image, state=img)
        if img["is_active"] == 0:
            #if img["is_valid"] == 1:
            self._deferred = self._device.omci_cc.send_active_image(self._to_image)
            self._deferred.addCallbacks(self.__activate_resp_success, self.__activate_fail)
            #else:
            #    self.fail()
        else:
            self.do_commit()

    def on_enter_busy(self):
        self.log.debug("on_enter_busy")
        self.reactor.callLater(3, self.activate)
        
    def on_enter_rebooting(self):
        self.log.debug("on_enter_rebooting")
        if self._timeout_dc == None:
            self._timeout_dc = self.reactor.callLater(self._timeout, self.fail)

    def on_exit_rebooting(self):
        self.log.debug("on_exit_rebooting")
        if self._timeout_dc and self._timeout_dc.active:
            self._timeout_dc.cancel()
            self._timeout_dc = None
    
    def on_enter_committing(self):
        # self.log.debug("on_enter_committing")
        img = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 
                                              self._to_image, ["is_active", "is_committed", "is_valid"])
        self.log.debug("on_enter_committing", instance=self._to_image, state=img)
        if (img['is_active'] == 0):
            self._retry += 1
            self.log.debug("do retry", retry=self._retry)
            self.reset()
        else:
            self._retry = 0
            self._deferred = self._device.omci_cc.send_commit_image(self._to_image)
            self._deferred.addCallbacks(self.__commit_success, self.__commit_fail)

    def on_enter_done(self):
        self.log.debug("on_enter_done")
        self._image_download.image_state = ImageDownload.IMAGE_ACTIVE
        self.ret_deferred.callback(self._to_image)

    def on_enter_failed(self):
        self.log.debug("on_enter_failed")
        self._image_download.image_state = ImageDownload.IMAGE_REVERT
        self.ret_deferred.errback(failure.Failure(Exception('ONU Software Activating Failed, instance ' + str(self._to_image))))
'''

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
                     # image_activate_stm_cls, 
                     advertise_events=True, local_dir=None, clock=None):
        """
        Class initialization

        :param omci_agent: (OpenOmciAgent) Agent
        :param dev_id    : (str) ONU Device ID
        :param dwld_stm_cls          : (ImageDownloadeSTM) Image download state machine class
        :param dwld_img_tasks        : (FileDownloadTask) file download task
        :param upgrade_onu_stm_cls   : (OmciSoftwareImageDownloadSTM) ONU Image upgrade state machine class
        :param upgrade_onu_tasks     : ({OmciSwImageUpgradeTask})
        # :param image_activate_stm_cls: (OmciSoftwareImageActivateSTM)
        """
        
        self.log = structlog.get_logger(device_id=dev_id)

        self._omci_agent = omci_agent
        self._device_id = dev_id
        self._dwld_stm_cls  = dwld_stm_cls
        # self._image_download_sm = None
        self._images = dict()
        self._download_task_cls = dwld_img_tasks['download-file'] 

        self._omci_upgrade_sm_cls = upgrade_onu_stm_cls
        self._omci_upgrade_task_cls = upgrade_onu_tasks['omci_upgrade_task']
        self._omci_upgrade_task = None
        self._omci_upgrade_deferred = None
        
        # self._omci_activate_img_sm_cls = image_activate_stm_cls
        # self._omci_activate_img_sm = None
        self.reactor = clock if clock is not None else reactor

        self._advertise_events = advertise_events
        # self._local_dir = None

        self._device = None
        # onu_dev = self._omci_agent.get_device(self._device_id)
        # assert device
        
        # self._local_dir = DEFAULT_LOCAL_ROOT + onu_dev.adapter_agent.name
        # self.log.debug("ImageAgent", local_dir=self._local_dir)
        
        
    def __get_standby_image_instance(self):
        instance_id = None
        instance_0 = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 0, ["is_active", "is_committed"])
        if instance_0['is_active'] == 1:
            instance_id = 1
        else:
            instance_1 = self._omci_agent.database.query(self._device_id, SoftwareImage.class_id, 1, ["is_active", "is_committed"])
            if instance_1['is_active'] == 1:
                instance_id = 0
        return instance_id

    def __clear_task(self, arg):
        self.__omci_upgrade_task = None

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
        self.log.debug("get_image", download=image_download)

        # if self._local_dir is None:
        #     onu_dev = self._omci_agent.get_device(self._device_id)
        #     assert onu_dev
        #     if image_download.local_dir is None:
        #         self._local_dir = ImageAgent.DEFAULT_LOCAL_ROOT + onu_dev.adapter_agent.name
        #     else:
        #         self._local_dir = image_download.local_dir + '/' + onu_dev.adapter_agent.name
            
            # self.log.debug("ImageAgent", local_dir=self._local_dir)
        #     image_download.local_dir = self._local_dir
            
        # if os.path.isfile(self._local_dir + '/' + image_download.name): # image file exists
        #     d = Deferred()
        #     self.reactor.callLater(0, d.callback, image_download)
        #     self.log.debug("Image file exists")
        #     return d

        img_dnld_sm = self._images.get(image_download.name)
        if img_dnld_sm is None:
            img_dnld_sm = self._dwld_stm_cls(self._omci_agent, # self._device_id, name, local_dir, remote_url, 
                                             image_download,
                                             self._download_task_cls,
                                             timeout_delay=timeout_delay,
                                             clock=self.reactor
                                            )
            self._images[image_download.name] = img_dnld_sm

        # if self._image_download_sm is None:
        #     self._image_download_sm = self._dwld_stm_cls(self._omci_agent, # self._device_id, name, local_dir, remote_url, 
        #                                                  image_download,
        #                                                  self._download_task_cls,
        #                                                  timeout_delay=timeout_delay,
        #                                                  clock=self.reactor
        #                                                 )
        # else:
        #     if self._image_download_sm.download_status.state != ImageDownload.DOWNLOAD_SUCCEEDED:
        #         self._image_download_sm.reset()
            
        d = img_dnld_sm.get_file()
        return d

    def cancel_download_image(self, name):
        img_dnld_sm = self._images.pop(name, None)
        if img_dnld_sm is not None:
            img_dnld_sm.stop()
            
            
    def onu_omci_download(self, image_dnld_name):
        """
        Start upgrading ONU.
        image_dnld: (ImageDownload)
        : Return Defer instance to get called after upgrading success or failed. 
        : Or return None if image does not exist
        """
        self.log.debug("onu_omci_download", image=image_dnld_name)

        image_dnld_sm = self._images.get(image_dnld_name)
        if image_dnld_sm is None:
            return None
            
        self._device = self._omci_agent.get_device(image_dnld_sm.status.id) if self._device is None else self._device

        # if restart:
        #     self.cancel_upgrade_onu()            
            
        if self._omci_upgrade_task is None:
            img_id = self.__get_standby_image_instance()
            self.log.debug("start task", image_Id=img_id, task=self._omci_upgrade_sm_cls)
            self._omci_upgrade_task = self._omci_upgrade_task_cls(img_id, 
                                                                  self._omci_upgrade_sm_cls, 
                                                                  self._omci_agent, 
                                                                  image_dnld_sm.status, clock=self.reactor)
            self.log.debug("task created but not started")
            # self._device.task_runner.start()
            self._omci_upgrade_deferred = self._device.task_runner.queue_task(self._omci_upgrade_task)
            self._omci_upgrade_deferred.addBoth(self.__clear_task)
        return self._omci_upgrade_deferred


    def cancel_upgrade_onu(self):
        self.log.debug("cancel_upgrade_onu")
        if self._omci_upgrade_task is not None:
            self.log.debug("cancel_upgrade_onu", running=self._omci_upgrade_task.running)
            # if self._omci_upgrade_task.running:
            self._omci_upgrade_task.stop()
            self._omci_upgrade_task = None
        if self._omci_upgrade_deferred is not None:
           self.reactor.callLater(0, self._omci_upgrade_deferred.cancel)
           self._omci_upgrade_deferred = None
           

    # def activate_onu_image(self, image_name):
    #     self.log.debug("activate_onu_image", image=image_name)
    #     img_dnld = self.get_image_status(image_name)
    #     if img_dnld is None:
    #         return None
            
    #     img_dnld.image_state = ImageDownload.IMAGE_INACTIVE    
    #     if self._omci_activate_img_sm is None:
    #         self._omci_activate_img_sm = self._omci_activate_img_sm_cls(self._omci_agent, self._device_id,
    #                                                                     self.__get_standby_image_instance(), 
    #                                                                     img_dnld, clock=self.reactor)
    #         return self._omci_activate_img_sm.start()
    #     else:
    #         return None
            
    def onu_bootup(self):
        if self._omci_upgrade_task is not None:
            self._omci_upgrade_task.onu_bootup()

    def get_image_status(self, image_name):
        """
          Return (ImageDownload)
        """
        sm = self._images.get(image_name)
        return sm.status if sm is not None else None
    
