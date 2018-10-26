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
from voltha.extensions.omci.tasks.mib_resync_task import MibResyncTask
from voltha.extensions.omci.omci_entities import GalEthernetProfile, GemPortNetworkCtp, \
    Ieee8021pMapperServiceProfile


class AdtnMibResyncTask(MibResyncTask):
    """
    ADTRAN MIB resynchronization Task

    The ADTRAN IBONT 602 does not report the current value of the GAL Ethernet
    Payload size, it is always 0.

    Also, the MEF EVC/EVC-MAP code monitors GEM Port CTP ME
    """
    def __init__(self, omci_agent, device_id):
        """
        Class initialization

        :param omci_agent: (OpenOMCIAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        super(AdtnMibResyncTask, self).__init__(omci_agent, device_id)
        self.omci_fixed = False

    def compare_mibs(self, db_copy, db_active):
        """
        Compare the our db_copy with the ONU's active copy

        :param db_copy: (dict) OpenOMCI's copy of the database
        :param db_active: (dict) ONU's database snapshot
        :return: (dict), (dict), (list)  Differences
        """
        on_olt_only, on_onu_only, attr_diffs = super(AdtnMibResyncTask, self).\
            compare_mibs(db_copy, db_active)

        if not self.omci_fixed:
            # Exclude 'max_gem_payload_size' in GAL Ethernet Profile
            attr_diffs = [attr for attr in attr_diffs
                          if attr[0] != GalEthernetProfile.class_id
                          or attr[2] != 'max_gem_payload_size']

            # Exclude any changes to GEM Port Network CTP
            attr_diffs = [attr for attr in attr_diffs
                          if attr[0] != GemPortNetworkCtp.class_id]

            if on_olt_only is not None:
                # Exclude IEEE 8021.p Mapper Service Profile from OLT Only as not
                # reported in current IBONT 602 software
                on_olt_only = [(cid, eid) for cid, eid in on_olt_only
                               if cid != Ieee8021pMapperServiceProfile.class_id]

        return on_olt_only, on_onu_only, attr_diffs
