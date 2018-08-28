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

import binascii
import structlog
from unittest import TestCase, TestSuite, skip
from voltha.extensions.omci.openomci_agent import OpenOMCIAgent
from voltha.extensions.omci.omci_entities import SoftwareImage
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_messages import \
        OmciStartSoftwareDownload, OmciStartSoftwareDownloadResponse, \
        OmciEndSoftwareDownload, OmciEndSoftwareDownloadResponse, \
        OmciDownloadSection, OmciDownloadSectionLast, OmciDownloadSectionResponse, \
        OmciActivateImage, OmciActivateImageResponse,  \
        OmciCommitImage, OmciCommitImageResponse
from voltha.protos.voltha_pb2 import ImageDownload
from voltha.protos.device_pb2 import Device

from tests.utests.voltha.extensions.omci.mock.mock_adapter_agent import MockAdapterAgent, MockCore
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.epollreactor import EPollReactor
from time import sleep

class TestOmciDownload(TestCase):
    # def __init__(self, device_id='1', image_file='/home/lcui/work/tmp/v_change.txt', **kwargs):
    #     self.device_id = device_id
    #     self.image_file = image_file
    #     super(TestOmciDownload, self).__init__(**kwargs)
    sw_dwld_resp = {
        'tid': '0001',
        'mid': '33',
        'did': '0A',
        'entity_class': '0007',
        'entity_id'   : '0000',
        'reason'      : '0000',
        'window_size' : '001F',
        'inst_num'    : '0001',
        'inst_id'     : '0000',
        'trailer'     : '00000028',
        'mic'         : '00000000'
    }
    
    # sw_dwld_resp = '0001330A000700000000001f010000'
     
    ### Test Functions ###
    def sim_receive_start_sw_download_resp(self, tid, eid, r=0):
        msg = OmciFrame(
                    transaction_id=tid,
                    message_type=OmciStartSoftwareDownloadResponse.message_id,
                    omci_message=OmciStartSoftwareDownloadResponse(
                        entity_class=0x7,
                        entity_id=eid,
                        result=r,
                        window_size=0x1F,
                        image_number=1,
                        instance_id=eid
                    )
              )
        self.device.omci_cc.receive_message(msg)

    def sim_receive_download_section_resp(self, tid, eid, section, r=0):
        msg = OmciFrame(
                    transaction_id=tid,
                    message_type=OmciDownloadSectionResponse.message_id,
                    omci_message=OmciDownloadSectionResponse(
                        entity_class=0x7,
                        entity_id=eid,
                        result=r,
                        section_number=section
                    )
              )
        self.device.omci_cc.receive_message(msg)

    def sim_receive_end_sw_download_resp(self, tid, eid, r=0):
        msg = OmciFrame(
                    transaction_id=tid,
                    message_type=OmciEndSoftwareDownloadResponse.message_id,
                    omci_message=OmciEndSoftwareDownloadResponse(
                        entity_class=0x7,
                        entity_id=eid,
                        result=r,
                        image_number=0x1,
                        instance_id=eid,
                        result0=0x0
                    )
              )
        self.device.omci_cc.receive_message(msg)

    def sim_receive_activate_image_resp(self, tid, eid, r=0):
        msg = OmciFrame(
                    transaction_id=tid,
                    message_type=OmciActivateImageResponse.message_id,
                    omci_message=OmciActivateImageResponse(
                        entity_class=0x7,
                        entity_id=eid,
                        result = r
                    ))
        self.device.omci_cc.receive_message(msg)

    def sim_receive_commit_image_resp(self, tid, eid, r=0):
        msg = OmciFrame(
                    transaction_id=tid,
                    message_type=OmciCommitImageResponse.message_id,
                    omci_message=OmciCommitImageResponse(
                        entity_class=0x7,
                        entity_id=eid,
                        result = r
                    ))
        self.device.omci_cc.receive_message(msg)
        
    def cb_after_send_omci(self, msg):
        self.log.debug("cb_after_send_omci")
        dmsg = OmciFrame(binascii.unhexlify(msg))
        tid = dmsg.fields['transaction_id']
        mid = dmsg.fields['message_type']
        dmsg_body = dmsg.fields['omci_message']
        eid = dmsg_body.fields['entity_id']

        # print("%X" % dmsg.fields['transaction_id'])
        # print("%X" % dmsg.fields['message_type'])
        # print("%X" % OmciActivateImage.message_id)
        # print("%X" % dmsg_body.fields['entity_id'])

        if mid == OmciStartSoftwareDownload.message_id:
            self.log.debug("response start download")
            self.reactor.callLater(0, self.sim_receive_start_sw_download_resp, tid, eid)
        elif mid == OmciEndSoftwareDownload.message_id:
            self.log.debug("response end download")
            if self._end_image_busy_try > 0:
                self.reactor.callLater(0, self.sim_receive_end_sw_download_resp, tid, eid, r=6)
                self._end_image_busy_try -= 1
            else:
                self.reactor.callLater(0, self.sim_receive_end_sw_download_resp, tid, eid)
        elif mid == OmciDownloadSection.message_id:
            self.log.debug("receive download section, not respond")
        elif mid == OmciDownloadSectionLast.message_id:
            self.log.debug("response download last section")
            self.reactor.callLater(0, self.sim_receive_download_section_resp, tid, eid, 
                                   section=dmsg_body.fields["section_number"])
        elif mid == OmciActivateImage.message_id:
            self.log.debug("response activate image")
            if self._act_image_busy_try > 0:
                self.reactor.callLater(0, self.sim_receive_activate_image_resp, tid, eid, r=6)
                self._act_image_busy_try -= 1
            else:
                self.reactor.callLater(0, self.sim_receive_activate_image_resp, tid, eid)
                self.reactor.callLater(2, self.device.image_agent.onu_bootup)
        elif mid == OmciCommitImage.message_id:
            self.log.debug("response commit image")
            self.reactor.callLater(0, self.sim_receive_commit_image_resp, tid, eid)
        else:
            self.log.debug("Unsupported message type", message_type=mid)
            
        self.defer = Deferred()
        self.defer.addCallback(self.cb_after_send_omci)
        self.adapter_agent.send_omci_defer = self.defer
        
    def setUp(self):
        self.log = structlog.get_logger()
        self.log.debug("do setup")
        self.device_id = '1'
        self._image_dnld = ImageDownload()
        self._image_dnld.id = '1'
        self._image_dnld.name = 'switchd_1012'
        # self._image_dnld.name = 'xgsont_4.4.4.006.img'
        self._image_dnld.url = 'http://192.168.100.222:9090/load/4.4.4.006.img'
        self._image_dnld.crc = 0
        self._image_dnld.local_dir = '/home/lcui/work/tmp'
        self._image_dnld.state = ImageDownload.DOWNLOAD_SUCCEEDED # ImageDownload.DOWNLOAD_UNKNOWN
        self._end_image_busy_try = 2
        self._act_image_busy_try = 0
        # self.image_file = '/home/lcui/work/tmp/v_change.txt'
        self.reactor = EPollReactor()
        self.defer = Deferred()
        self.adapter_agent = MockAdapterAgent(self.defer)
        self.defer.addCallback(self.cb_after_send_omci)
        pb2_dev = Device(id='1')
        self.adapter_agent.add_device(pb2_dev)
        self.core = self.adapter_agent.core
        self.omci_agent = OpenOMCIAgent(self.core, clock=self.reactor)
        self.device = self.omci_agent.add_device(self.device_id, self.adapter_agent)
        self.omci_agent.start()
        self.omci_agent.database.add('1')
        self.omci_agent.database.set('1', SoftwareImage.class_id, 0, {"is_committed": 1, "is_active": 1, "is_valid": 1})
        self.omci_agent.database.set('1', SoftwareImage.class_id, 1, {"is_committed": 0, "is_active": 0, "is_valid": 1})
        
    def tearDown(self):
        self.log.debug("Test is Done")
        self.omci_agent.database.remove('1')
        self.device = None

    def stop(self):
        self.reactor.stop()
        self.log.debug("stopped");

    def get_omci_msg(self, *args, **kargs):
        m = ''
        for s in args:
            m += s
        m = m.ljust(80, '0')
        return m + kargs['trailer'] + kargs['mic']

    def sim_receive_sw_download_resp2(self):
        r = self.get_omci_msg(self.sw_dwld_resp['tid'], self.sw_dwld_resp['mid'], 
                              self.sw_dwld_resp['did'], self.sw_dwld_resp['entity_class'], 
                              self.sw_dwld_resp['entity_id'], self.sw_dwld_resp['reason'], 
                              self.sw_dwld_resp['window_size'], self.sw_dwld_resp['inst_num'], self.sw_dwld_resp['inst_id'], 
                              trailer=self.sw_dwld_resp['trailer'], mic=self.sw_dwld_resp['mic'])
        data = binascii.unhexlify(r)
        #msg = OmciFrame(data)
        #print(msg.fields['transaction_id'])
        #print(msg.fields['omci'])
        self.device.omci_cc.receive_message(data)

    def sw_action_success(self, instance_id, device_id):
        self.log.debug("Action Success", device_id=device_id, entity_id=instance_id)
        self.reactor.callLater(0, self.onu_do_activate)
        
    def sw_action2_success(self, instance_id, device_id):
        self.log.debug("Action2 Success", device_id=device_id, entity_id=instance_id)

    def sw_action_fail(self, fail, device_id):
        self.log.debug("Finally Failed", device_id=device_id)
        self.log.debug(fail)
        
    # def test_onu_do_activate(self):
    def onu_do_activate(self):
        self.log.debug("do test_onu_do_activate") 
        self.defer = self.device.do_onu_image_activate(self._image_dnld.name)
        self.defer.addCallbacks(self.sw_action2_success, self.sw_action_fail, callbackArgs=(self.device_id,), errbackArgs=(self.device_id,))
        self.reactor.callLater(100, self.stop)
        # self.reactor.run()
        
    @skip("for Jenkins Verification")
    def test_onu_do_software_upgrade(self):
        self.log.debug("do test_onu_do_software_upgrade", download=self._image_dnld)
        dr = self.omci_agent.database.query('1', SoftwareImage.class_id, 0, "is_committed")
        self.defer = self.device.do_onu_software_download(self._image_dnld)
        self.defer.addCallbacks(self.sw_action_success, self.sw_action_fail, callbackArgs=(self.device_id,), errbackArgs=(self.device_id,))
        # self.defer.addCallbacks(self.sw_action_success, self.sw_action_fail) #, errbackArgs=(self.device_id,))
        # self.reactor.callLater(1, self.sim_receive_start_sw_download_resp)
        # self.reactor.callLater(12, self.stop)
        self.reactor.run()
        
    @skip("Not used")
    def test_omci_message(self):
        self.log.debug("do test_omci_message") 
        r = self.get_omci_msg(self.sw_dwld_resp['tid'], self.sw_dwld_resp['mid'], 
                              self.sw_dwld_resp['did'], self.sw_dwld_resp['entity_class'], 
                              self.sw_dwld_resp['entity_id'], self.sw_dwld_resp['reason'], 
                              self.sw_dwld_resp['window_size'], self.sw_dwld_resp['inst_num'], self.sw_dwld_resp['inst_id'], 
                              trailer=self.sw_dwld_resp['trailer'], mic=self.sw_dwld_resp['mic'])
        data = binascii.unhexlify(r)
        msg = OmciFrame(data)
        self.log.debug(binascii.hexlify(str(msg)))
        # print("%04X" % msg.fields['transaction_id'])
        # print("%02X" % msg.fields['message_type'])
        # print("%02X" % msg.fields['omci'])
        # print("%X" % msg.fields['omci_message'])

    @skip("Not used")
    def test_omci_message2(self):
        self.log.debug("do test_omci_message2") 
        msg = OmciFrame(
                    transaction_id=0x0001,
                    message_type=OmciStartSoftwareDownloadResponse.message_id,
                    omci_message=OmciStartSoftwareDownloadResponse(
                        entity_class=0x7,
                        entity_id=0x0,
                        result=0x0,
                        window_size=0x1F,
                        image_number=1,
                        instance_id=0
                    )
              )
        self.log.debug(binascii.hexlify(str(msg)))
        
this_suite = TestSuite()
# this_suite.addTest(TestOmciDownload('test_onu_do_software_upgrade'))
# this_suite.addTest(TestOmciDownload('test_onu_do_activate'))

