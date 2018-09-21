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

import os
import structlog
import xmltodict
from twisted.internet import reactor
from twisted.internet.defer import returnValue, inlineCallbacks
from voltha.protos.device_pb2 import ImageDownload
from voltha.protos.common_pb2 import AdminState

log = structlog.get_logger()

# TODO: Following two would be good provisionable parameters
DEFAULT_AUTO_AGE_MINUTES = 10
DEFAULT_MAX_JOB_RUN_SECONDS = 3600 * 4     # Some OLT files are 250MB+


class Download(object):
    """Class to wrap an image download"""

    def __init__(self, handler, request, protocols):
        self._handler = handler
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

        self._age_out_period = DEFAULT_AUTO_AGE_MINUTES
        self._max_execution = DEFAULT_MAX_JOB_RUN_SECONDS

    def __str__(self):
        return "ImageDownload: {}".format(self.name)

    @staticmethod
    def create(handler, request, supported_protocols):
        """
        Create and start a new image download

        :param handler: (AdtranDeviceHandler) Device download is for
        :param request: (ImageDownload) Request
        :param supported_protocols: (list) download methods allowed (http, tftp, ...)
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

    @inlineCallbacks
    def start_download(self):
        import uuid
        log.info('download-start', name=self.name)
        if not self.parse_url():
            self._download_failed()
            returnValue('failed url parsing')

        self._download_state = ImageDownload.DOWNLOAD_STARTED
        self._failure_reason = ImageDownload.NO_ERROR

        ##############################################################
        # Configure the file server profile
        try:
            self._additional_info = 'Configuring Download Server profile'
            self._server_profile_name = 'VOLTHA.download.{}'.format(uuid.uuid4())
            profile = self.server_profile_xml
            yield self._handler.netconf_client.edit_config(profile)

        except Exception as e:
            log.exception('server-profile', e=e)
            self._server_profile_name = None
            self._failure_reason = ImageDownload.UNKNOWN_ERROR
            self._additional_info += ': Failure: {}'.format(e.message)
            self._download_failed()
            raise

        ##############################################################
        # Configure the software download maintenance job
        try:
            self._additional_info = 'Configuring Image Download Job'
            self._download_job_name = 'VOLTHA.download.{}'.format(uuid.uuid4())
            job = self.download_job_xml
            yield self._handler.netconf_client.edit_config(job)

        except Exception as e:
            log.exception('server-profile', e=e)
            self._download_job_name = None
            self._failure_reason = ImageDownload.UNKNOWN_ERROR
            self._additional_info += ': Failure: {}'.format(e.message)
            self._download_failed()
            raise

        ##############################################################
        # Schedule a task to monitor the download
        try:
            self._additional_info = 'Monitoring download status'
            self._deferred = reactor.callLater(0.5, self.monitor_download_status)

        except Exception as e:
            log.exception('server-profile', e=e)
            self._failure_reason = ImageDownload.UNKNOWN_ERROR
            self._additional_info += ': Failure: {}'.format(e.message)
            self._download_failed()
            raise

        returnValue('started')

    def parse_url(self):
        from urllib3 import util, exceptions
        try:
            results = util.parse_url(self._url)

            # Server info
            self._scheme = results.scheme.lower()
            if self._scheme not in self._supported_protocols:
                self._failure_reason = ImageDownload.INVALID_URL
                self._additional_info = "Unsupported file transfer protocol: {}".format(results.scheme)
                return False

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

    @property
    def server_profile_xml(self):
        assert self._scheme in ['http', 'https', 'ftp', 'sftp', 'tftp'], 'Invalid protocol'

        xml = """
              <file-servers xmlns="http://www.adtran.com/ns/yang/adtran-file-servers">
                <profiles>
                  <profile>"""

        xml += '<name>{}</name>'.format(self._server_profile_name)
        xml += '<connection-profile>'
        xml += '  <host>{}</host>'.format(self._host)
        xml += '  <port>{}</port>'.format(self._port) if self._port is not None else '<use-standard-port/>'

        if self._scheme in ['http', 'https']:
            xml += '  <protocol '
            xml += 'xmlns:adtn-file-srv-https="http://www.adtran.com/ns/yang/adtran-file-servers-https">' +\
                   'adtn-file-srv-https:{}'.format(self._scheme)
            xml += '  </protocol>'

        elif self._scheme == 'sftp':
            xml += '  <protocol '
            xml += 'xmlns:adtn-file-srv-sftp="http://www.adtran.com/ns/yang/adtran-file-servers-sftp">' +\
                   'adtn-file-srv-sftp:sftp'
            xml += '  </protocol>'

        elif self._scheme in ['ftp', 'tftp']:
            xml += '<protocol>adtn-file-srv:{}</protocol>'.format(self._scheme)

        if self._auth is not None:
            user_pass = self._auth.split(':')
            xml += '<username>{}</username>'.format(user_pass[0])
            xml += '<password>$0${}</password>'.format("".join(user_pass[1:]))
        # And the trailer
        xml += """
                 </connection-profile>
               </profile>
             </profiles>
            </file-servers>
        """
        return xml

    @property
    def download_job_xml(self):
        # TODO: May want to support notifications
        # TODO: Not sure about this name for the entity
        entity = 'main 0'
        xml = """
              <maintenance-jobs xmlns="http://www.adtran.com/ns/yang/adtran-maintenance-jobs" xmlns:adtn-phys-sw-mnt="http://www.adtran.com/ns/yang/adtran-physical-software-maintenance">
                <maintenance-job>
                  <name>{}</name>
                  <enabled>true</enabled>
                  <notify-enabled>false</notify-enabled>
                  <maximum-execution-time>{}</maximum-execution-time>
                  <run-once>true</run-once>
                  <adtn-phys-sw-mnt:download-software>
                    <adtn-phys-sw-mnt:physical-entity>{}</adtn-phys-sw-mnt:physical-entity>
                    <adtn-phys-sw-mnt:software-name>software</adtn-phys-sw-mnt:software-name>
                    <adtn-phys-sw-mnt:remote-file>
                      <adtn-phys-sw-mnt:file-server-profile>{}</adtn-phys-sw-mnt:file-server-profile>
                      <adtn-phys-sw-mnt:filename>{}</adtn-phys-sw-mnt:filename>
        """.format(self._download_job_name, self._max_execution, entity,
                   self._server_profile_name, self._name)

        if self._path is not None:
            xml += """
                          <adtn-phys-sw-mnt:filepath>{}</adtn-phys-sw-mnt:filepath>
                """.format(self._path)

        xml += """
                    </adtn-phys-sw-mnt:remote-file>
                  </adtn-phys-sw-mnt:download-software>
                </maintenance-job>
              </maintenance-jobs>
        """
        return xml

    @property
    def download_status_xml(self):
        xml = """
              <filter>
                <maintenance-jobs-state xmlns="http://www.adtran.com/ns/yang/adtran-maintenance-jobs">
                  <maintenance-job>
                    <name>{}</name>
                  </maintenance-job>
                </maintenance-jobs-state>
              </filter>
          """.format(self._download_job_name)
        return xml

    @property
    def delete_server_profile_xml(self):
        xml = """
        <file-servers xmlns="http://www.adtran.com/ns/yang/adtran-file-servers">
          <profiles operation="delete">
            <profile>
              <name>{}</name>
            </profile>
           </profiles>
        </file-servers>
        """.format(self._server_profile_name)
        return xml

    @property
    def delete_download_job_xml(self):
        xml = """
        <maintenance-jobs xmlns="http://www.adtran.com/ns/yang/adtran-maintenance-jobs">
          <maintenance-job operation="delete">>
            <name>{}</name>
          </maintenance-job>
        </maintenance-jobs>
        """.format(self._download_job_name)
        return xml

    @inlineCallbacks
    def monitor_download_status(self):
        log.debug('monitor-download', name=self.name)
        try:
            results = yield self._handler.netconf_client.get(self.download_status_xml)

            result_dict = xmltodict.parse(results.data_xml)
            entries = result_dict['data']['maintenance-jobs-state']['maintenance-job']

            name = entries.get('name')
            assert name == self._download_job_name, 'The job status name does not match. {} != {}'.format(name, self.name)
            self._download_state = self.monitor_state_to_download_state(entries['state']['#text'])

            completed = entries['timestamps'].get('completed-timestamp')
            started = entries['timestamps'].get('start-timestamp')

            if self._download_state == ImageDownload.DOWNLOAD_FAILED:
                self._failure_reason = ImageDownload.UNKNOWN_ERROR
                self._additional_info = entries['error'].get('error-message')

            elif self._download_state == ImageDownload.INSUFFICIENT_SPACE:
                self._failure_reason = ImageDownload.INSUFFICIENT_SPACE
                self._additional_info = entries['error'].get('error-message')

            elif self._download_state == ImageDownload.DOWNLOAD_STARTED:
                self._failure_reason = ImageDownload.NO_ERROR
                self._additional_info = 'Download started at {}'.format(started)

            elif self._download_state == ImageDownload.DOWNLOAD_SUCCEEDED:
                self._failure_reason = ImageDownload.NO_ERROR
                self._additional_info = 'Download completed at {}'.format(completed)
            else:
                raise NotImplemented('Unsupported state')

            done = self._download_state in [ImageDownload.DOWNLOAD_FAILED,
                                            ImageDownload.DOWNLOAD_SUCCEEDED,
                                            ImageDownload.INSUFFICIENT_SPACE]

        except Exception as e:
            log.exception('protocols', e=e)
            done = False

        if not done:
            self._deferred = reactor.callLater(1, self.monitor_download_status)

        returnValue('done' if done else 'not-done-yet')

    def _download_failed(self):
        log.info('download-failed', name=self.name)

        self._cancel_deferred()
        self._download_state = ImageDownload.DOWNLOAD_FAILED

        # Cleanup NETCONF
        reactor.callLater(0, self._cleanup_download_job, 20)
        reactor.callLater(0, self._cleanup_server_profile, 20)
        # TODO: Do we signal any completion due to failure?

    def _download_complete(self):
        log.info('download-completed', name=self.name)

        self._cancel_deferred()
        self._download_state = ImageDownload.DOWNLOAD_SUCCEEDED
        self._downloaded_octets = 123456
        self._failure_reason = ImageDownload.NO_ERROR

        reactor.callLater(0, self._cleanup_download_job, 20)
        reactor.callLater(0, self._cleanup_server_profile, 20)
        # TODO: How do we signal completion?

        device = self._handler.adapter_agent.get_device(self.device_id)
        if device is not None:
            # restore admin state to enabled
            device.admin_state = AdminState.ENABLED
            self._handler.adapter_agent.update_device(device)

    def cancel_download(self, request):
        log.info('cancel-sw-download', name=self.name)

        self._cancel_deferred()

        try:
            # initiate cancelling software download to device at success
            # delete image download record

            self._handler.adapter_agent.delete_image_download(request)

            device = self._handler.adapter_agent.get_device(self.device_id)
            if device is not None:
                # restore admin state to enabled
                device.admin_state = AdminState.ENABLED
                self._handler.adapter_agent.update_device(device)

        except Exception as e:
            log.exception(e.message)

        reactor.callLater(0, self._cleanup_download_job, 20)
        reactor.callLater(0, self._cleanup_server_profile, 20)

    @inlineCallbacks
    def _cleanup_server_profile(self, retries, attempt=1):
        log.info('cleanup-server', name=self.name,
                 profile=self._server_profile_name,
                 attempt=attempt, remaining=retries)

        if self._server_profile_name is not None:
            try:
                profile = self.delete_server_profile_xml
                yield self._handler.netconf_client.edit_config(profile)
                self._server_profile_name = None

            except Exception as e:
                log.exception(e.message)
                if retries > 0:
                    reactor.callLater(attempt * 60, self._cleanup_download_job,
                                      retries - 1, attempt + 1)

    @inlineCallbacks
    def _cleanup_download_job(self, retries, attempt=1):
        log.info('cleanup-download', name=self.name,
                 profile=self._download_job_name,
                 attempt=attempt, remaining=retries)

        if self._download_job_name is not None:
            try:
                job = self.delete_download_job_xml
                yield self._handler.netconf_client.edit_config(job)
                self._download_job_name = None

            except Exception as e:
                log.exception(e.message)
                if retries > 0:
                    reactor.callLater(attempt * 60, self._cleanup_download_job,
                                      retries - 1, attempt + 1)

    @inlineCallbacks
    def activate_image(self):
        log.info('download-activate', name=self.name)

        if self._download_state == ImageDownload.DOWNLOAD_SUCCEEDED:
            pass   # TODO: Implement
            self._image_state = ImageDownload.IMAGE_ACTIVE

        returnValue('TODO: Implement this')

    @inlineCallbacks
    def revert_image(self):
        log.info('download-revert', name=self.name)

        if self._download_state == ImageDownload.DOWNLOAD_SUCCEEDED:
            pass   # TODO: Implement
            self._image_state = ImageDownload.IMAGE_INACTIVE

        returnValue('TODO: Implement this')

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
        log.info('download-software-state', result=result, state=state, name=self.name)
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
        log.info('download-activate-state', result=result, state=state, name=self.name)
        assert result is not None, 'Invalid state'
        return result

    @staticmethod
    def clear_all(client):
        """
        Remove all file server profiles and download jobs
        :param client: (ncclient) NETCONF Client to use
        """
        from twisted.internet import defer
        del_fs_xml = """
            <file-servers xmlns="http://www.adtran.com/ns/yang/adtran-file-servers">
              <profiles operation="delete"/>
            </file-servers>
            """
        del_job_xml = """
            <maintenance-jobs operation="delete" xmlns="http://www.adtran.com/ns/yang/adtran-maintenance-jobs"/>
            """
        dl = [client.edit_config(del_fs_xml, ignore_delete_error=True),
              client.edit_config(del_job_xml, ignore_delete_error=True)]

        return defer.gatherResults(dl, consumeErrors=True)
