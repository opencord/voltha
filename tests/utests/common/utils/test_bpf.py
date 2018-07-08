# Copyright 2017-present Open Networking Foundation
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
from unittest import TestCase, main

from scapy.layers.l2 import Ether, Dot1Q

from common.frameio.frameio import BpfProgramFilter


class TestBpf(TestCase):

    def test_bpf1(self):
        vid = 4090
        pcp = 7
        frame_match = 'ether[14:2] = 0x{:01x}{:03x}'.format(pcp << 1, vid)
        filter = BpfProgramFilter(frame_match)
        self.assertTrue(filter(str(Ether()/Dot1Q(prio=pcp, vlan=vid))))
        self.assertFalse(filter(str(Ether()/Dot1Q(prio=pcp, vlan=4000))))

    def test_bpf2(self):
        vid1 = 4090
        pcp1 = 7
        frame_match_case1 = 'ether[14:2] = 0x{:01x}{:03x}'.format(
            pcp1 << 1, vid1)

        vid2 = 4000
        frame_match_case2 = '(ether[14:2] & 0xfff) = 0x{:03x}'.format(vid2)

        filter = BpfProgramFilter('{} or {}'.format(
            frame_match_case1, frame_match_case2))
        self.assertTrue(filter(str(Ether()/Dot1Q(prio=pcp1, vlan=vid1))))
        self.assertTrue(filter(str(Ether()/Dot1Q(vlan=vid2))))
        self.assertFalse(filter(str(Ether()/Dot1Q(vlan=4001))))


if __name__ == '__main__':
    main()
