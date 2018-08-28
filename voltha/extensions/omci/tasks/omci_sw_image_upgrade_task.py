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
import structlog
from task import Task
from twisted.internet import reactor
from voltha.protos.voltha_pb2 import ImageDownload

class OmciSwImageUpgradeTask(Task):
    name = "OMCI Software Image Upgrade Task"


    def __init__(self, img_id, omci_upgrade_sm_cls, omci_agent, image_download, clock=None):
        super(OmciSwImageUpgradeTask, self).__init__(OmciSwImageUpgradeTask.name, omci_agent, image_download.id,
                                                     exclusive=False,
                                                     watchdog_timeout=45)
        self.log.debug("OmciSwImageUpgradeTask create ", image_id=img_id)
        self._image_id = img_id
        self._omci_upgrade_sm_cls = omci_upgrade_sm_cls
        # self._omci_agent = omci_agent
        self._image_download = image_download
        self.reactor = clock if clock is not None else reactor
        self._omci_upgrade_sm = None
        self.log.debug("OmciSwImageUpgradeTask create end", image_id=img_id)

    @property 
    def status(self):
        return self._image_download
        
    def start(self):
        self.log.debug("OmciSwImageUpgradeTask start")
        super(OmciSwImageUpgradeTask, self).start()
        if self._omci_upgrade_sm is None:
            self._omci_upgrade_sm = self._omci_upgrade_sm_cls(self._image_id, self.omci_agent, self._image_download, clock=self.reactor)
            d = self._omci_upgrade_sm.start()
            d.chainDeferred(self.deferred)
        #else:
        #    if restart:
        #        self._omci_upgrade_sm.reset_image()

    def stop(self):
        self.log.debug("OmciSwImageUpgradeTask stop")
        if self._omci_upgrade_sm is not None:
            self._omci_upgrade_sm.stop()
            self._omci_upgrade_sm = None
    
    def onu_bootup(self):
        self.log.debug("onu_bootup", state=self._omci_upgrade_sm.status.image_state);
        if self._omci_upgrade_sm is not None \
            and self._omci_upgrade_sm.status.image_state == ImageDownload.IMAGE_ACTIVATE:
            self._omci_upgrade_sm.do_commit()
    
