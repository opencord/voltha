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


class FileDownloadTask(Task):
    name = "Image File Download Task"

    def __init__(self, omci_agent, device_id, url, local_path):
        super(FileDownloadTask, self).__init__(FileDownloadTask.name, omci_agent, device_id,
                                               exclusive=False,
                                               watchdog_timeout=45)
        self.url = url
        self.local_path = local_path
        # self.log.debug('{} running'.format(FileDownloadTask.name))

    def start(self):
        self.log.debug('{} running'.format(FileDownloadTask.name))
        # reactor.callLater(1, self.deferred.callback, 'device {} success downloaded {} '.format(self.device_id, self.url))
        try:
            # local_filename = url.split('/')[-1]
            dir_name = os.path.dirname(self.local_path)
            if not os.path.exists(dir_name):
                os.makedirs(dir_name)

            self.strobe_watchdog()
            r = requests.get(self.url, stream=True)

            with open(self.local_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024):
                    self.strobe_watchdog()
                    if chunk: # filter out keep-alive new chunks
                        f.write(chunk)
            self.deferred.callback('device {} success downloaded {} '.format(self.device_id, self.url))
        except Exception as e:
            #self.deferred.errback(KeyError('device {} failed downloaded {} '.format(self.device_id, self.url)))
            self.deferred.errback(failure.Failure(e))
            
    def stop(self):
        self.cancel_deferred()
        super(FileDownloadTask, self).stop()

