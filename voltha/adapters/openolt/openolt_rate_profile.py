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

import collections

'''
Subscriber rate profiles will be fetched from the KV store once
the tech profile story is implemented.
'''

RateProfile = collections.namedtuple('RateProfile', 'id cir pir burst')

downstream_rate_profile = [
    RateProfile(id=0, cir=5000, pir=5000, burst=5000),
    RateProfile(id=1, cir=10000, pir=10000, burst=10000),
    RateProfile(id=2, cir=100000, pir=100000, burst=100000),
    RateProfile(id=3, cir=1000000, pir=1000000, burst=1000000)
]
