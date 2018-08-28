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
from task import Task
from twisted.internet.defer import inlineCallbacks, TimeoutError, failure, AlreadyCalledError
from twisted.internet import reactor
from voltha.extensions.omci.omci_defs import ReasonCodes
import requests
import os
import time

class FileDownloadTask(Task):
    name = "Image File Download Task"
    CHUNK_SIZE = 1024
    
    def __init__(self, omci_agent, img_dnld, clock= None): #device_id, url, local_path)
        super(FileDownloadTask, self).__init__(FileDownloadTask.name, omci_agent, img_dnld.id,
                                               exclusive=False,
                                               watchdog_timeout=45)
        # self.url = url
        # self.local_path = local_path
        self._image_download = img_dnld
        self.reactor = clock if clock is not None else reactor
        self._local_deferred = None
        # self._request = None
        # self._file = None
        # self.log.debug('{} running'.format(FileDownloadTask.name))

    # def __save_data(self):
    #     chunk = self._request.iter_content(chunk_size=FileDownloadTask.CHUNK_SIZE)
    #     if len(chunk) == 0:
    #         self._file.close()
    #         self.deferred.callback(self._image_download)
    #     else:
    #         self._file.write(chunk)
    #         self._image_download.downloaded_bytes += len(chunk)
    #         self.reactor.callLater(0, self.__save_data)        

    @inlineCallbacks
    def perform_download_data(self):
        try:
            r = requests.get(self._image_download.url, stream=True)
            with open(self._image_download.local_dir + '/' + self._image_download.name, 'wb') as f:
                for chunk in r.iter_content(chunk_size=FileDownloadTask.CHUNK_SIZE):
                    self.strobe_watchdog()
                    if chunk: # filter out keep-alive new chunks
                        yield f.write(chunk)
                        self._image_download.file_size += len(chunk)
                        # yield time.sleep(1)
            self.deferred.callback(self._image_download)
        except Exception as e:
            self.deferred.errback(failure.Failure(e))
        
    def start(self):
        super(FileDownloadTask, self).start()
        if not os.path.exists(self._image_download.local_dir):
            os.makedirs(self._image_download.local_dir)

        self.strobe_watchdog()
        self._image_download.file_size = 0
        self._local_deferred = self.reactor.callLater(0, self.perform_download_data)
        # try:
        #     if not os.path.exists(self._image_download.local_dir):
        #         os.makedirs(self._image_download.local_dir)

        #     self.strobe_watchdog()
        #     self._image_download.downloaded_bytes = 0
        #     self.reactor.callLater(0, self.perform_download_data)
            
            # self._request = requests.get(self._image_download.url, stream=True)
            # with open(self._image_download.local_dir + '/' + self._image_download.name, 'wb') as f:
            #     for chunk in r.iter_content(chunk_size=FileDownloadTask.CHUNK_SIZE):
            #         self.strobe_watchdog()
            #         if chunk: # filter out keep-alive new chunks
            #             f.write(chunk)
            #             self._image_download.downloaded_bytes += len(chunk)
            
            # self.deferred.callback(self._image_download)
        # except Exception as e:
        #     self.deferred.errback(failure.Failure(e))
            
    # def stop(self):
    #     # self.cancel_deferred()
    #     super(FileDownloadTask, self).stop()

    def cancel_deferred(self):
        self.log.debug('FileDownloadTask cancel_deferred')
        super(FileDownloadTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

