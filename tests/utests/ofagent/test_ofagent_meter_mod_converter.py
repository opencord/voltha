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


from unittest import main, TestCase
import structlog
from loxi.of13.message import meter_mod
from ofagent.converter import to_grpc
from ofagent.loxi.of13 import const
from random import randint
from protobuf_to_dict import protobuf_to_dict
from ofagent.loxi.of13.message import meter_mod

log = structlog.get_logger()


class test_of_agent_vcore_connection(TestCase):

    def test_meter_mod_loxi_to_grpc_converter(self):
        from ofagent.loxi.of13 import meter_band

        assertion_check_keys = dict()
        meter_bands = list()

        command_list = [const.OFPMC_ADD, const.OFPMC_MODIFY, const.OFPMC_DELETE]
        flag_list = [const.OFPMF_KBPS, const.OFPMF_PKTPS, const.OFPMF_BURST, const.OFPMF_STATS]
        meter_band_constructs = [meter_band.dscp_remark, meter_band.drop, meter_band.experimenter]

        assertion_check_keys['meter_band_entry_cnt'] = randint(0, 20)
        assertion_check_keys['xid_instance'] = randint(0, 0xFFFFFFFF)
        assertion_check_keys['command_instance'] = command_list[randint(0, len(command_list) - 1)]
        assertion_check_keys['flag_instance'] = flag_list[randint(0, len(flag_list) - 1)]

        for i in range(0, assertion_check_keys['meter_band_entry_cnt']):
            meter_band = meter_band_constructs[randint(0, len(meter_band_constructs)-1)]()
            assertion_check_keys['meter_band_type_' + str(i)] = meter_band.type
            meter_bands.append(meter_band)

        of_meter_mod_req = meter_mod(xid=assertion_check_keys['xid_instance'],
                                     command=assertion_check_keys['command_instance'],
                                     flags=assertion_check_keys['flag_instance'],
                                     meters=meter_bands)

        req = to_grpc(of_meter_mod_req)
        request = protobuf_to_dict(req)

        if request.has_key('flags'):
            self.assertEqual(request['flags'], assertion_check_keys['flag_instance'])

        if request.has_key('command'):
            self.assertEqual(request['command'], assertion_check_keys['command_instance'])

        if request.has_key('bands'):
            self.assertEqual(assertion_check_keys['meter_band_entry_cnt'], len(request['bands']))

            name_suffix = 0
            for i in request['bands']:
                self.assertEqual(i['type'], assertion_check_keys['meter_band_type_' + str(name_suffix)])
                name_suffix = name_suffix+1


if __name__ == '__main__':
    main()
