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
from twisted.internet import reactor
from twisted.internet.defer import failure, inlineCallbacks, TimeoutError, returnValue
from voltha.extensions.omci.omci_defs import ReasonCodes, EntityOperations
from voltha.extensions.omci.omci_me import MEFrame
from voltha.extensions.omci.omci_frame import OmciFrame
from voltha.extensions.omci.omci_cc import DEFAULT_OMCI_TIMEOUT
from voltha.extensions.omci.omci_messages import OmciGet
from voltha.extensions.omci.omci_fields import OmciTableField

RC = ReasonCodes
OP = EntityOperations


class GetException(Exception):
    pass


class OmciGetRequest(Task):
    """
    OpenOMCI Get an OMCI ME Instance Attributes

    Upon completion, the Task deferred callback is invoked with a reference of
    this Task object.

    The Task has an initializer option (allow_failure) that will retry all
    requested attributes if the original request fails with a status code of
    9 (Attributes failed or unknown). This result means that an attribute
    is not supported by the ONU or that a mandatory/optional attribute could
    not be executed by the ONU, even if it is supported, for example,
    because of a range or type violation.
    """
    task_priority = 128
    name = "ONU OMCI Get Task"

    def __init__(self, omci_agent, device_id, entity_class, entity_id, attributes,
                 exclusive=True, allow_failure=False):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param entity_class: (EntityClass) ME Class to retrieve
        :param entity_id: (int) ME Class instance ID to retrieve
        :param attributes: (list or set) Name of attributes to retrieve
        :param exclusive: (bool) True if this GET request Task exclusively own the
                                 OMCI-CC while running. Default: True
        :param allow_failure: (bool) If true, attempt to get all valid attributes
                                     if the original request receives an error
                                     code of 9 (Attributes failed or unknown).
        """
        super(OmciGetRequest, self).__init__(OmciGetRequest.name,
                                             omci_agent,
                                             device_id,
                                             priority=OmciGetRequest.task_priority,
                                             exclusive=exclusive)
        self._device = omci_agent.get_device(device_id)
        self._entity_class = entity_class
        self._entity_id = entity_id
        self._attributes = attributes
        self._allow_failure = allow_failure
        self._failed_or_unknown_attributes = set()
        self._results = None
        self._local_deferred = None

    def cancel_deferred(self):
        super(OmciGetRequest, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    @property
    def me_class(self):
        """The OMCI Managed Entity Class associated with this request"""
        return self._entity_class

    @property
    def entity_id(self):
        """The ME Entity ID associated with this request"""
        return self._entity_id

    @property
    def attributes(self):
        """
        Return a dictionary of attributes for the request if the Get was
        successfully completed.  None otherwise
        """
        if self._results is None:
            return None

        omci_msg = self._results.fields['omci_message'].fields
        return omci_msg['data'] if 'data' in omci_msg else None

    @property
    def success_code(self):
        """
        Return the OMCI success/reason code for the Get Response.
        """
        if self._results is None:
            return None

        return self._results.fields['omci_message'].fields['success_code']

    @property
    def raw_results(self):
        """
        Return the raw Get Response OMCIFrame
        """
        return self._results

    def start(self):
        """
        Start MIB Capabilities task
        """
        super(OmciGetRequest, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_get_omci)

    @property
    def failed_or_unknown_attributes(self):
        """
        Returns a set attributes that failed or unknown in the original get
        request that resulted in an initial status code of 9 (Attributes
        failed or unknown).

        :return: (set of str) attributes
        """
        return self._failed_or_unknown_attributes

    @inlineCallbacks
    def perform_get_omci(self):
        """
        Perform the initial get request
        """
        self.log.info('perform-get', entity_class=self._entity_class,
                      entity_id=self._entity_id, attributes=self._attributes)
        try:
            # If one or more attributes is a table attribute, get it separately
            def is_table_attr(attr):
                index = self._entity_class.attribute_name_to_index_map[attr]
                attr_def = self._entity_class.attributes[index]
                return isinstance(attr_def.field, OmciTableField)

            first_attributes = {attr for attr in self._attributes if not is_table_attr(attr)}
            table_attributes = {attr for attr in self._attributes if is_table_attr(attr)}

            frame = MEFrame(self._entity_class, self._entity_id, first_attributes).get()
            self.strobe_watchdog()
            results = yield self._device.omci_cc.send(frame)

            status = results.fields['omci_message'].fields['success_code']
            self.log.debug('perform-get-status', status=status)

            # Success?
            if status == RC.Success.value:
                self._results = results
                results_omci = results.fields['omci_message'].fields

                # Were all attributes fetched?
                missing_attr = frame.fields['omci_message'].fields['attributes_mask'] ^ \
                    results_omci['attributes_mask']

                if missing_attr > 0 or len(table_attributes) > 0:
                    self.log.info('perform-get-missing', num_missing=missing_attr,
                                  table_attr=table_attributes)
                    self.strobe_watchdog()
                    self._local_deferred = reactor.callLater(0,
                                                             self.perform_get_missing_attributes,
                                                             missing_attr,
                                                             table_attributes)
                    returnValue(self._local_deferred)

            elif status == RC.AttributeFailure.value:
                # What failed?  Note if only one attribute was attempted, then
                # that is an overall failure

                if not self._allow_failure or len(self._attributes) <= 1:
                    raise GetException('Get failed with status code: {}'.
                                       format(RC.AttributeFailure.value))

                self.strobe_watchdog()
                self._local_deferred = reactor.callLater(0,
                                                         self.perform_get_failed_attributes,
                                                         results,
                                                         self._attributes)
                returnValue(self._local_deferred)

            else:
                raise GetException('Get failed with status code: {}'.format(status))

            self.log.debug('get-completed')
            self.deferred.callback(self)

        except TimeoutError as e:
            self.deferred.errback(failure.Failure(e))

        except Exception as e:
            self.log.exception('perform-get', e=e, class_id=self._entity_class,
                               entity_id=self._entity_id, attributes=self._attributes)
            self.deferred.errback(failure.Failure(e))

    @inlineCallbacks
    def perform_get_missing_attributes(self, missing_attr, table_attributes):
        """
        This method is called when the original Get requests completes with success
        but not all attributes were returned.  This can happen if one or more of the
        attributes would have exceeded the space available in the OMCI frame.

        This routine iterates through the missing attributes and attempts to retrieve
        the ones that were missing.

        :param missing_attr: (int) Missing attributes bitmask
        :param table_attributes: (set) Attributes that need table get/get-next support
        """
        self.log.debug('perform-get-missing', attrs=missing_attr, tbl=table_attributes)

        # Retrieve missing attributes first (if any)
        results_omci = self._results.fields['omci_message'].fields

        for index in xrange(16):
            attr_mask = 1 << index

            if attr_mask & missing_attr:
                # Get this attribute
                frame = OmciFrame(
                    transaction_id=None,  # OMCI-CC will set
                    message_type=OmciGet.message_id,
                    omci_message=OmciGet(
                        entity_class=self._entity_class.class_id,
                        entity_id=self._entity_id,
                        attributes_mask=attr_mask
                    )
                )
                try:
                    self.strobe_watchdog()
                    get_results = yield self._device.omci_cc.send(frame)

                    get_omci = get_results.fields['omci_message'].fields
                    if get_omci['success_code'] != RC.Success.value:
                        continue

                    assert attr_mask == get_omci['attributes_mask'], 'wrong attribute'
                    results_omci['attributes_mask'] |= attr_mask

                    if results_omci.get('data') is None:
                        results_omci['data'] = dict()

                    results_omci['data'].update(get_omci['data'])

                except TimeoutError:
                    self.log.debug('missing-timeout')

                except Exception as e:
                    self.log.exception('missing-failure', e=e)

        # Now any table attributes. OMCI_CC handles background get/get-next sequencing
        for tbl_attr in table_attributes:
            attr_mask = self._entity_class.mask_for(tbl_attr)
            frame = OmciFrame(
                    transaction_id=None,  # OMCI-CC will set
                    message_type=OmciGet.message_id,
                    omci_message=OmciGet(
                            entity_class=self._entity_class.class_id,
                            entity_id=self._entity_id,
                            attributes_mask=attr_mask
                    )
            )
            try:
                timeout = 2 * DEFAULT_OMCI_TIMEOUT  # Multiple frames expected
                self.strobe_watchdog()
                get_results = yield self._device.omci_cc.send(frame,
                                                              timeout=timeout)
                self.strobe_watchdog()
                get_omci = get_results.fields['omci_message'].fields
                if get_omci['success_code'] != RC.Success.value:
                    continue

                if results_omci.get('data') is None:
                    results_omci['data'] = dict()

                results_omci['data'].update(get_omci['data'])

            except TimeoutError:
                self.log.debug('tbl-attr-timeout')

            except Exception as e:
                self.log.exception('tbl-attr-timeout', e=e)

        self.deferred.callback(self)

    @inlineCallbacks
    def perform_get_failed_attributes(self, tmp_results, attributes):
        """

        :param tmp_results:
        :param attributes:
        :return:
        """
        self.log.debug('perform-get-failed', attrs=attributes)

        for attr in attributes:
            try:
                frame = MEFrame(self._entity_class, self._entity_id, {attr}).get()

                self.strobe_watchdog()
                results = yield self._device.omci_cc.send(frame)

                status = results.fields['omci_message'].fields['success_code']

                if status == RC.AttributeFailure.value:
                    self.log.debug('unknown-or-invalid-attribute', attr=attr, status=status)
                    self._failed_or_unknown_attributes.add(attr)

                elif status != RC.Success.value:
                    self.log.warn('invalid-get', class_id=self._entity_class,
                                  attribute=attr, status=status)
                    self._failed_or_unknown_attributes.add(attr)

                else:
                    # Add to partial results and correct the status
                    tmp_results.fields['omci_message'].fields['success_code'] = status
                    tmp_results.fields['omci_message'].fields['attributes_mask'] |= \
                        results.fields['omci_message'].fields['attributes_mask']

                    if tmp_results.fields['omci_message'].fields.get('data') is None:
                        tmp_results.fields['omci_message'].fields['data'] = dict()

                    tmp_results.fields['omci_message'].fields['data'][attr] = \
                        results.fields['omci_message'].fields['data'][attr]

            except TimeoutError as e:
                self.log.debug('attr-timeout')

            except Exception as e:
                self.log.exception('attr-failure', e=e)

        self._results = tmp_results
        self.deferred.callback(self)
