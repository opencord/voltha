#
# Copyright 2018 the original author or authors.
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
from enum import IntEnum
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, failure, TimeoutError
from voltha.extensions.omci.omci_defs import ReasonCodes, EntityOperations
from voltha.extensions.omci.omci_me import OntGFrame
from voltha.extensions.omci.omci_cc import DEFAULT_OMCI_TIMEOUT

RC = ReasonCodes
OP = EntityOperations


class RebootException(Exception):
    pass


class DeviceBusy(Exception):
    pass


class RebootFlags(IntEnum):
    Reboot_Unconditionally = 0,
    Reboot_If_No_POTS_VoIP_In_Progress = 1,
    Reboot_If_No_Emergency_Call_In_Progress = 2


class OmciRebootRequest(Task):
    """
    OpenOMCI routine to request reboot of an ONU
    """
    task_priority = Task.MAX_PRIORITY
    name = "ONU OMCI Reboot Task"
    # adopt the global default
    DEFAULT_REBOOT_TIMEOUT = DEFAULT_OMCI_TIMEOUT

    def __init__(self, omci_agent, device_id,
                 flags=RebootFlags.Reboot_Unconditionally,
                 timeout=DEFAULT_REBOOT_TIMEOUT):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param flags: (RebootFlags) Reboot condition
        """
        super(OmciRebootRequest, self).__init__(OmciRebootRequest.name,
                                                omci_agent,
                                                device_id,
                                                priority=OmciRebootRequest.task_priority,
                                                exclusive=True)
        self._device = omci_agent.get_device(device_id)
        self._flags = flags
        self._timeout = timeout
        self._local_deferred = None

    def cancel_deferred(self):
        super(OmciRebootRequest, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """ Start task """
        super(OmciRebootRequest, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_reboot)

    @inlineCallbacks
    def perform_reboot(self):
        """
        Perform the reboot requests

        Depending on the ONU implementation, a response may not be returned. For this
        reason, a timeout is considered successful.
        """
        self.log.info('perform-reboot')

        try:
            frame = OntGFrame().reboot(reboot_code=self._flags)
            self.strobe_watchdog()
            results = yield self._device.omci_cc.send(frame, timeout=self._timeout)

            status = results.fields['omci_message'].fields['success_code']
            self.log.debug('reboot-status', status=status)

            # Did it fail
            if status != RC.Success.value:
                if self._flags != RebootFlags.Reboot_Unconditionally and\
                        status == RC.DeviceBusy.value:
                    raise DeviceBusy('ONU is busy, try again later')
                else:
                    msg = 'Reboot request failed with status {}'.format(status)
                    raise RebootException(msg)

            self.log.info('reboot-success')
            self.deferred.callback(self)

        except TimeoutError:
            self.log.info('timeout', msg='Request timeout is not considered an error')
            self.deferred.callback(None)

        except DeviceBusy as e:
            self.log.warn('perform-reboot', msg=e)
            self.deferred.errback(failure.Failure(e))

        except Exception as e:
            self.log.exception('perform-reboot', e=e)
            self.deferred.errback(failure.Failure(e))
