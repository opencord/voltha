# Copyright 2017-present CIG, Inc.
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

import os
import structlog
import xmltodict
from twisted.internet import reactor
from twisted.internet.defer import returnValue, inlineCallbacks
from voltha.protos.device_pb2 import ImageDownload
from voltha.protos.common_pb2 import AdminState
from cig_olt_zmq import *
#from voltha.adapters.cig_olt.protos.olt_common_pb2 import *
#from voltha.adapters.cig_olt.protos.olt_d_pb2 import *
from voltha.protos.olt_common_pb2 import *
from voltha.protos.olt_d_pb2 import *

log = structlog.get_logger()


class Download(object):
    """Class to wrap an image download"""

    def __init__(self, handler, request, protocols):
        self._olt = handler
        self._deferred = None
        self.device_id = request.id
        self._name = request.name
        self._url = request.url
        self._crc = request.crc
        self._version = request.image_version
        self._local = request.local_dir
        self._save_config = request.save_config
        self._supported_protocols = protocols

        self._download_state = ImageDownload.DOWNLOAD_UNKNOWN
        self._failure_reason = ImageDownload.UNKNOWN_ERROR
        self._image_state = ImageDownload.IMAGE_UNKNOWN
        self._additional_info = ''
        self._downloaded_octets = 0

        # Server profile info
        self._server_profile_name = None
        self._scheme = None
        self._host = ''
        self._port = None
        self._path = ''
        self._auth = None

        # Download job info
        self._download_job_name = None
        self._chech_deferred =None

    def __str__(self):
        return "ImageDownload: {}".format(self.name)

    @staticmethod
    def create(handler, request, supported_protocols):
        """
        Create and start a new image download

        :param handler: (AdtranDeviceHandler) Device download is for
        :param done_deferred: (Deferred) deferred to fire on completion
        :param request: (ImageDownload) Request
        """
        download = Download(handler, request, supported_protocols)
        download._deferred = reactor.callLater(0, download.start_download)

        return download

    @property
    def name(self):
        return self._name

    @property
    def download_state(self):
        return self._download_state

    @property
    def failure_reason(self):
        return self._failure_reason

    @property
    def image_state(self):
        return self._image_state

    @property
    def additional_info(self):
        return self._additional_info

    @property
    def downloaded_bytes(self):
        return self._downloaded_octets

    @property
    def profile_name(self):
        return self._server_profile_name

    def _cancel_deferred(self):
        d, self._deferred = self._deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except Exception as e:
            pass

    def check_download_status(self):
        log.info('*** check download status ***')
        self._download_state = ImageDownload.DOWNLOAD_SUCCEEDED
        self._failure_reason = ImageDownload.NO_ERROR 
        self._download_complete()
        

    #@inlineCallbacks
    def start_download(self):
        import uuid
        log.info('download-start', name=self.name)
        if not self.parse_url():
            self._download_failed()
            log.info('failed url parsing', name=self.name)
            return
            #returnValue('failed url parsing')

        self._download_state = ImageDownload.DOWNLOAD_STARTED
        self._failure_reason = ImageDownload.NO_ERROR

        #send msg to oltd to start download
        self.image_cfg_msg_send(IMAGE_CMD_DOWNLOAD)
        
        log.info('start download *************', name=self.name)
        self._chech_deferred = reactor.callLater(120, self.check_download_status)
        return self._chech_deferred

    def parse_url(self):
        from urllib3 import util, exceptions
        try:
            results = util.parse_url(self._url)

            # Server info
            self._scheme = results.scheme.lower()
            #if self._scheme not in self._supported_protocols:
                #self._failure_reason = ImageDownload.INVALID_URL
                #self._additional_info = "Unsupported file transfer protocol: {}".format(results.scheme)
                #return False

            self._host = results.host
            self._port = results.port
            self._path = results.path
            self._auth = results.auth
            return True

        except exceptions.LocationValueError as e:
            self._failure_reason = ImageDownload.INVALID_URL
            self._additional_info = e.message
            return False

        except Exception as e:
            self._failure_reason = ImageDownload.UNKNOWN_ERROR
            self._additional_info = e.message
            return False

    def _download_failed(self):
        log.info('download-failed', name=self.name)

        self._cancel_deferred()
        self._download_state = ImageDownload.DOWNLOAD_FAILED

        # Cleanup NETCONF

        #reactor.callLater(0, self._cleanup_download_job, 20)
        #reactor.callLater(0, self._cleanup_server_profile, 20)
        # TODO: Do we signal any completion due to failure?

    def _download_complete(self):
        log.info('download-completed', name=self.name)

        self._cancel_deferred()
        self._download_state = ImageDownload.DOWNLOAD_SUCCEEDED
        self._downloaded_octets = 123456
        self._failure_reason = ImageDownload.NO_ERROR

        #reactor.callLater(0, self._cleanup_download_job, 20)
        #reactor.callLater(0, self._cleanup_server_profile, 20)
        # TODO: How do we signal completion?

        device = self._olt.adapter_agent.get_device(self.device_id)
        if device is not None:
            # restore admin state to enabled
            device.admin_state = AdminState.ENABLED
            self._olt.adapter_agent.update_device(device)

    #@inlineCallbacks
    def cancel_download(self, request):
        log.info('cancel-sw-download', name=self.name)

        self._cancel_deferred()

        try:
            # initiate cancelling software download to device at success
            # delete image download record

            self._olt.adapter_agent.delete_image_download(request)

            device = self._olt.adapter_agent.get_device(self.device_id)
            if device is not None:
                # restore admin state to enabled
                device.admin_state = AdminState.ENABLED
                self._olt.adapter_agent.update_device(device)


            #send msg to oltd to cancel download
            self.image_cfg_msg_send(IMAGE_CMD_CANCEL)

        except Exception as e:
            log.exception(e.message)

        #reactor.callLater(0, self._cleanup_download_job, 20)
        #reactor.callLater(0, self._cleanup_server_profile, 20)


    #@inlineCallbacks
    def activate_image(self):
        log.info('download-activate', name=self.name)

        if self._download_state == ImageDownload.DOWNLOAD_SUCCEEDED:
            pass   # TODO: Implement
            self._image_state = ImageDownload.IMAGE_ACTIVE

        #send msg to oltd to activate image
        self.image_cfg_msg_send(IMAGE_CMD_ACTIVETE)
        
        #returnValue('TODO: Implement this')

    #@inlineCallbacks
    def revert_image(self):
        log.info('download-revert', name=self.name)

        if self._download_state == ImageDownload.DOWNLOAD_SUCCEEDED:
            pass   # TODO: Implement
            self._image_state = ImageDownload.IMAGE_INACTIVE

        #send msg to oltd to revert image
        self.image_cfg_msg_send(IMAGE_CMD_REVERT)
        
        #returnValue('TODO: Implement this')

    def monitor_state_to_download_state(self, state):
        if ':' in state:
            state = state.split(':')[-1]
        result = {
            'downloading-software': ImageDownload.DOWNLOAD_STARTED,       # currently downloading software
            'storing-software': ImageDownload.DOWNLOAD_STARTED,           # successfully downloaded the required software and is storing it to memory
            'software-stored': ImageDownload.DOWNLOAD_SUCCEEDED,          # successfully downloaded the required software and has stored it successfully to memory
            'software-download-failed': ImageDownload.DOWNLOAD_FAILED,    # unsuccessfully attemptedto download the required software
            'invalid-software': ImageDownload.DOWNLOAD_FAILED,            # successfully downloaded the required software but the software was determined to be invalid
            'software-storage-failed': ImageDownload.INSUFFICIENT_SPACE,  # successfully downloaded the required software but was unable to successfully stored it to memory
        }.get(state.lower(), None)
        log.info('download-state', result=result, state=state, name=self.name)
        assert result is not None, 'Invalid state'
        return result

    def monitor_state_to_activate_state(self, state):
        if ':' in state:
            state = state.split(':')[-1]
        result = {
            'enabling-software': ImageDownload.IMAGE_ACTIVATE,         # currently enabling the software
            'software-enabled': ImageDownload.IMAGE_ACTIVE,            # successfully enabled the required software
            'enable-software-failed': ImageDownload.IMAGE_INACTIVE,    # unsuccessfully attempted to enable the required software revision
            'activating-software': ImageDownload.IMAGE_ACTIVATE,       # currently activating the software
            'software-activated': ImageDownload.IMAGE_ACTIVE,          # successfully activated the required software. The job terminated successfully
            'activate-software-failed': ImageDownload.IMAGE_INACTIVE,  # unsuccessfully attempted to activate the required software revision
            'committing-software': ImageDownload.IMAGE_ACTIVATE,       # currently committing the software
            'software-committed': ImageDownload.IMAGE_ACTIVATE,        # successfully committed the required software. The job terminated successfully
            'commit-software-failed': ImageDownload.IMAGE_INACTIVE,    # unsuccessfully attempted to commit the required software revision
        }.get(state.lower(), None)
        log.info('download-state', result=result, state=state, name=self.name)
        assert result is not None, 'Invalid state'
        return result


    def image_cfg_msg_send(self, cmd_type):
            
        try:
            mgr_hdr = OltMsgCommonHdr(
                type=OLT_D_IMAGE_CFG,
                src_appId=OLT_APPID_VOLTHA,
                sync=0
            )

            data=mgr_hdr.SerializeToString()

            self._olt.zmq_client_async.async_send(data, 1)
            if cmd_type == IMAGE_CMD_DOWNLOAD:
                image_cfg = OltDImageCfg(
                    name = self._name,
                    cmd = cmd_type,
                    url = self._url,
                    crc = self._crc,
                    version = self._version
                )
            else:
                image_cfg = OltDImageCfg(
                    name = self._name,
                    cmd = cmd_type
                )
            data=image_cfg.SerializeToString()
            self._olt.zmq_client_async.async_send(data, 0)
        except Exception as e:
            log.exception('Exception during image cfg processing', e=e)









        
