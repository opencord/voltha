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
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_defs import *
from voltha.extensions.omci.omci_entities import *
from voltha.extensions.omci.omci_messages import *

# abbreviations
OP = EntityOperations
RC = ReasonCodes


class MockOnu(object):
    """
    Minimal class that acts line an ONU. The Mock OLT handler will call into this
    object with OMCI frames that it will respond to appropriately
    """
    def __init__(self, serial_number, adapter_agent, handler_id):
        self.serial_number = serial_number
        self._adapter_agent = adapter_agent     # TODO: Remove any unused attributes
        self._handler_id = handler_id
        self.mib_data_sync = 0                  # Assume at reboot!

        # NOTE: when creating response frames, use the basic method of constructing
        #       these frames as the encoding created is unit-tested elsewhere
        self._omci_response = {
            OP.Get.value: {
                CircuitPack.class_id: {
                    257: OmciFrame(transaction_id=0,  # Will get replaced
                                   message_type=OmciGetResponse.message_id,
                                   omci_message=OmciGetResponse(
                                       entity_class=CircuitPack.class_id,
                                       entity_id=0,
                                       success_code=RC.Success.value,
                                       attributes_mask=CircuitPack.mask_for('number_of_ports'),
                                       data=OmciMaskedData('value',
                                                           entity_class=CircuitPack.class_id,
                                                           attributes_mask=CircuitPack.mask_for('number_of_ports'))
                                   ))
                },
                # Additional OMCI GET request responses here if needed
            },
            OP.GetNext.value: {},
            OP.Create.value: {
                # TODO: Create some OMCI CREATE request responses here.

                # def send_create_gal_ethernet_profile(self,
                #                                      entity_id,
                #                                      max_gem_payload_size):
                #     frame = OmciFrame(
                #         transaction_id=self.get_tx_id(),
                #         message_type=OmciCreate.message_id,
                #         omci_message=OmciCreate(
                #             entity_class=GalEthernetProfile.class_id,
                #             entity_id=entity_id,
                #             data=dict(
                #                 max_gem_payload_size=max_gem_payload_size
                #             )
                #         )
                #     )
                #     self.send_omci_message(frame)
            },
            OP.Set.value: {
                # TODO: Create some OMCI SET request responses here.

                # def send_set_admin_state(self,
                #                          entity_id,
                #                          admin_state):
                #     data = dict(
                #         administrative_state=admin_state
                #     )
                #     frame = OmciFrame(
                #         transaction_id=self.get_tx_id(),
                #         message_type=OmciSet.message_id,
                #         omci_message=OmciSet(
                #             entity_class=OntG.class_id,
                #             entity_id=entity_id,
                #             attributes_mask=OntG.mask_for(*data.keys()),
                #             data=data
                #         )
                #     )
                #     self.send_omci_message(frame)

            },
            OP.Delete.value: {
                # TODO: Create some OMCI DELETE responses here.
            },
            OP.MibReset.value: {
                OntData.class_id: {
                    0: OmciFrame(transaction_id=0,  # Will get replaced
                                 message_type=OmciMibResetResponse.message_id,
                                 omci_message=OmciMibResetResponse(
                                     entity_class=OntData.class_id,
                                     entity_id=0,
                                     success_code=RC.Success.value
                                 ))
                }
            },
            OP.MibUpload.value: {
                OntData.class_id: {
                    0: OmciFrame(transaction_id=0,  # Will get replaced
                                 message_type=OmciMibUploadResponse.message_id,
                                 omci_message=OmciMibUploadResponse(
                                     entity_class=OntData.class_id,
                                     entity_id=0,
                                     number_of_commands=3  # Should match list size for MibUploadNext below
                                 ))
                }
            },
            # OP.MibUploadNext.value: {
            #     OntData.class_id: {
            #         0: [
            #             OmciFrame(transaction_id=0,
            #                       message_type=OmciMibUploadNextResponse.message_id,
            #                       omci_message=OmciMibUploadNextResponse(
            #                           entity_class=OntData.class_id,
            #                           entity_id=0,
            #                           object_entity_id=0,        # TODO: Pick one
            #                           object_attributes_mask=0,  # TODO: Pick one
            #                           object_data=None           # TODO: Pick one
            #                       )),
            #             OmciFrame(transaction_id=0,
            #                       message_type=OmciMibUploadNextResponse.message_id,
            #                       omci_message=OmciMibUploadNextResponse(
            #                           entity_class=OntData.class_id,
            #                           entity_id=0,
            #                           object_entity_id=0,        # TODO: Pick one
            #                           object_attributes_mask=0,  # TODO: Pick one
            #                           object_data=None           # TODO: Pick one
            #                       )),
            #             OmciFrame(transaction_id=0,
            #                       message_type=OmciMibUploadNextResponse.message_id,
            #                       omci_message=OmciMibUploadNextResponse(
            #                           entity_class=OntData.class_id,
            #                           entity_id=0,
            #                           object_entity_id=0,        # TODO: Pick one
            #                           object_attributes_mask=0,  # TODO: Pick one
            #                           object_data=None           # TODO: Pick one
            #                       )),
            #         ]
            #     }
            # },
            OP.Reboot.value: {
                OntData.class_id: {
                    0: OmciFrame(transaction_id=0,  # Will get replaced
                                 message_type=OmciRebootResponse.message_id,
                                 omci_message=OmciRebootResponse(
                                     entity_class=OntG.class_id,
                                     entity_id=0,
                                     success_code=RC.Success.value
                                 ))
                }
            },
        }
        # TODO: Support Autonomous ONU messages as well

    def tearDown(self):
        """Test case cleanup"""
        pass

    def _request_to_response_type(self, message_type):
        return {
            OP.Create.value: OmciCreateResponse,
            OP.Delete.value: OmciDeleteResponse,
            OP.Set.value: OmciSetResponse,
            OP.Get.value: OmciGetResponse,
            OP.GetNext.value: OmciGetNextResponse,
            OP.MibUpload.value: OmciMibUploadResponse,
            OP.MibUploadNext.value: OmciMibUploadNextResponse,
            OP.MibReset.value: OmciMibResetResponse,
            OP.Reboot.value: OmciRebootResponse,
        }.get(message_type & 0x1F, None)

    def rx_omci_frame(self, msg):
        try:
            frame = OmciFrame(msg.decode('hex'))
            response = None
            response_type = self._request_to_response_type(frame.fields['message_type'])
            transaction_id = frame.fields['transaction_id']

            omci_message = frame.fields.get('omci_message')

            class_id = omci_message.fields.get('entity_class') \
                if omci_message is not None else None
            instance_id = omci_message.fields.get('entity_id') \
                if omci_message is not None else None

            # Look up hardcode responses based on class and instance ID. If found
            # return the response, otherwise send back an error

            if response_type is None:
                status = RC.ProcessingError.value
            elif class_id is None:
                status = RC.UnknownEntity.value
            elif instance_id is None:
                status = RC.UnknownInstance.value
            else:
                status = RC.Success.value
                try:
                    response_id = response_type.message_id & 0x1f
                    response = self._omci_response[response_id][class_id][instance_id]

                    if response_id == OP.MibUploadNext.value:
                        # Special case. Need to get requested entry
                        assert isinstance(response, list)
                        pass
                        pass
                        pass
                        pass

                    if isinstance(omci_message, OmciGetNext):
                        response = response[omci_message.fields['command_sequence_number']]

                    if isinstance(response, dict):
                        if response['failures'] > 0:
                            response['failures'] -= 1
                            return None
                        else: response = response['frame']

                    response.fields['transaction_id'] = transaction_id
                    if 'success_code' in response.fields['omci_message'].fields:
                        response.fields['omci_message'].fields['success_code'] = status

                    if status == RC.Success.value:
                        if response_type.message_id in [OmciCreateResponse.message_id,
                                                        OmciDeleteResponse.message_id,
                                                        OmciSetResponse.message_id]:
                            self.mib_data_sync += 1
                            if self.mib_data_sync > 255:
                                self.mib_data_sync = 1
                        elif response_type.message_id == OmciMibResetResponse.message_id:
                            self.mib_data_sync = 0

                except KeyError as e:
                    bad_key = e.args[0]
                    if bad_key == class_id:
                        status = RC.UnknownEntity.value
                    elif bad_key == instance_id:
                        status = RC.UnknownInstance.value
                    else:
                        status = RC.ProcessingError.value

            if status != RC.Success.value and \
                    response_type not in [OmciMibUploadResponse,
                                          OmciMibUploadNextResponse]:
                response = OmciFrame(transaction_id=transaction_id,
                                     message_type=response_type.message_id,
                                     omci_message=response_type(
                                         entity_class=class_id,
                                         entity_id=instance_id,
                                         success_code=status
                                     ))
            return response

        except Exception as e:
            pass

    @property
    def proxy_address(self, device_id='1'):
        if self._proxy_address is None:
            self._proxy_address = Device.ProxyAddress(
                device_id=device_id,
                channel_group_id=1,
                channel_id=1,
                channel_termination="XGSPON",
                onu_id=20,
                onu_session_id=1)

        return self._proxy_address

