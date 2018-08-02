#
# Copyright 2018 the original author or authors.
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
#

DEFAULT_ONU_BW_PROFILE = "default"
DEFAULT_ONU_PIR = 1000000  # 1Gbps


class OpenOltBW(object):

    def __init__(self, log, proxy):
        self.log = log
        self.proxy = proxy

    def pir(self, serial_number):
        bw = 0
        try:
            bw = self.proxy.get(
                '/traffic_descriptor_profiles/{}'.format(serial_number))
        except KeyError:
            self.log.debug('bandwidth not configured',
                          serial_number=serial_number)
            try:
                bw = self.proxy.get('/traffic_descriptor_profiles/{}' \
                                    .format(DEFAULT_ONU_BW_PROFILE))
            except KeyError:
                return DEFAULT_ONU_PIR

        return bw.maximum_bandwidth
