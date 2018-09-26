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
"""
Implementation for the interface of KV store of flow and bal flow mapping
"""
import structlog
import json
from zope.interface import implementer
from voltha.adapters.asfvolt16_olt.kv_store_interface import KvStoreInterface
from voltha.core.config.config_backend import ConsulStore
from voltha.core.config.config_backend import EtcdStore

# KV store uses this prefix to store flows info
PATH_PREFIX = 'asfvolt16_flow_store'

log = structlog.get_logger()

@implementer(KvStoreInterface)
class Asfvolt16KvStore(object):

    def __init__(self, backend, host, port):
        """
        based on backend ('consul' and 'etcd' use the host and port
        to create of the respective object
        :param backend: Type of backend storage (etcd or consul)
        :param host: host ip info for backend storage
        :param port: port for the backend storage
        """
        try:
            if backend == 'consul':
                self.kv_store = ConsulStore(host, port, PATH_PREFIX)
            elif backend == 'etcd':
                self.kv_store = EtcdStore(host, port, PATH_PREFIX)
            else:
                log.error('Invalid-backend')
                raise Exception("Invalid-backend-for-kv-store")
        except Exception as e:
            log.exception("exception-in-init", e=e)

    # Used for incremental flow, as we are getting remove flow cookies,
    # So instead of evaluating, we are just getting the mapping info
    # from kv store
    def get_flows_to_remove_info(self, device_id, flows):
        # store flows to be removed
        flows_to_remove_list = []
        id = device_id.encode('ascii', 'ignore')

        try:
            # Preparing cookie info list from received remove flow
            for flow in flows:
                cookie_info = self.kv_store[id + '/' + str(flow.cookie)]
                if cookie_info:
                    log.debug("cookie-info-exist", cookie=flow.cookie,
                              cookie_info=cookie_info)
                    flows_to_remove_list.append(json.loads(cookie_info))
                else:
                    log.debug("cookie-info-does-not-exist", cookie=flow.cookie)

        except Exception as e:
            log.exception("evaulating-flows-to-remove-info", e=e)

        return flows_to_remove_list

    # Used for bulk flow update, as we are getting bulk flow cookies,
    # So we evalute based on the curent flows present in kv store
    def get_flows_to_remove(self, device_id, flows):
        # store the flows present in the db
        current_flows_list = []

        # store flows to be removed
        flows_to_remove_list = []
        id = device_id.encode('ascii', 'ignore')

        # Get all the flows already present in the consul
        try:
            # Get all the flows already present in the consul
            # Preparing cookie list from flows present in the KV store
            kv_store_flows = self.kv_store._kv_get(PATH_PREFIX + '/' + id,
                                                   recurse=True)
            if kv_store_flows is None:
                return flows_to_remove_list

            for kv_store_flow in kv_store_flows:
                value = kv_store_flow['Value']
                current_flows_list.append(json.loads(value))

            # Preparing cookie list from bulk flow received
            bulk_update_flow_cookie_list = [flow.cookie for flow in flows]

            # Evaluating the flows need to be removed
            # current_flows not present in bulk_flow
            for current_flow in current_flows_list:
                cookie = current_flow.keys()[0]
                if long(cookie) not in bulk_update_flow_cookie_list:
                    flows_to_remove_list.append(current_flow[cookie])

        except Exception as e:
            log.exception("evaulating-flows-to-remove", e=e)

        return flows_to_remove_list

    def get_flows_to_add(self, device_id, flows):
        # store the flows present in the db
        current_flows_list = []
        id = device_id.encode('ascii', 'ignore')

        try:
            # Get all the flows already present in the consul
            # Preparing cookie set from flows present in the KV store
            kv_store_flows = self.kv_store._kv_get(PATH_PREFIX + '/' + id,
                                                   recurse=True)
            if kv_store_flows is not None:
                for kv_store_flow in kv_store_flows:
                    value = kv_store_flow['Value']
                    current_flows_list.append(json.loads(value))

            current_flow_cookie_set = set(long(current_flow.keys()[0])
                                          for current_flow in current_flows_list)
            # Preparing cookie set from bulk flow received
            bulk_update_flow_cookie_set = set(flow.cookie for flow in flows)

            # Evaluating the list of flows newly to be added
            flow_to_add_set = bulk_update_flow_cookie_set.difference \
                                             (current_flow_cookie_set)
            flows_to_add_list = list(flow_to_add_set)

        except Exception as e:
            log.exception("evaluating-flows-to-add", e=e)

        return flows_to_add_list

    def add_to_kv_store(self, device_id, new_flow_mapping_list):
        # store the flows present in the db
        current_flows_list = []
        id = device_id.encode('ascii', 'ignore')

        try:
            log.debug("incremental-flows-to-be-added-to-kv-store",
                      flows=new_flow_mapping_list)
            # Key is the cookie id, extracted from the key stored in new_flow_mapping_list
            for flow in new_flow_mapping_list:
                self.kv_store[id + '/' + str(flow.keys()[0])] = json.dumps(flow)

        except Exception as e:
            log.exception("incremental-flow-add-to-kv-store", e=e)

    def remove_from_kv_store(self, device_id, flows_to_remove):
        id = device_id.encode('ascii', 'ignore')

        try:
            log.debug("incremental-flows-to-be-removed-from-kv-store",
                      flows=flows_to_remove)
            # remove the flows based on cookie id from kv store
            for cookie in flows_to_remove:
                del self.kv_store[id + '/' + str(cookie)]

        except Exception as e:
            log.exception("incremental-flow-remove-from-kv-store", e=e)

    def update_kv_store(self, device_id, new_flow_mapping_list, flows):
        # store the flows present in the db
        current_flows_list = []
        id = device_id.encode('ascii', 'ignore')

        try:
            # Get all the flows already present in the consul
            # Preparing cookie set from flows present in the KV store
            kv_store_flows = self.kv_store._kv_get(PATH_PREFIX + '/' + id,
                                                   recurse=True)
            if kv_store_flows is not None:
                for kv_store_flow in kv_store_flows:
                    value = kv_store_flow['Value']
                    current_flows_list.append(json.loads(value))

            current_flow_cookie_set = set(long(current_flow.keys()[0])
                                          for current_flow in current_flows_list)

            # Preparing cookie set from flows added newly
            new_flow_added_cookie_set = set(new_flow.keys()[0]
                                            for new_flow in new_flow_mapping_list)

            # Preparing cookie set from bulk flow received
            bulk_update_flow_cookie_set = set(flow.cookie for flow in flows)

            # Evaluating flows to be removed, remove from KV store
            remove_flows_list = list(current_flow_cookie_set.difference \
                                              (bulk_update_flow_cookie_set))
            log.debug("bulk-flows-to-be-removed-from-kv-store",
                      flows=remove_flows_list)

            for cookie in remove_flows_list:
                del self.kv_store[id + '/' + str(cookie)]

            # Evaluating flows need to be added newly to KV, add to KV
            new_flows_list = list(new_flow_added_cookie_set.difference \
                                            (current_flow_cookie_set))
            log.debug("bulk-flows-to-be-added-to-kv-store", flows=new_flows_list)

            for new_flow in new_flows_list:
                for fl in new_flow_mapping_list:
                    if fl.keys()[0] == new_flow:
                        self.kv_store[id + '/' + str(new_flow)] = json.dumps(fl)

        except Exception as e:
            log.exception("bulk-flow-update-kv-store", e=e)


    def clear_kv_store(self, device_id):
        id = device_id.encode('ascii', 'ignore')
        try:
            # Recurse flow is not working as cache is not getting cleared
            # So extracting all flows using GET and deleting each flow
            #kv_store_clear_flows = self.kv_store._kv_delete(PATH_PREFIX + '/' \
            #                                                + id, recurse=True)

            # Get all the flows present in the consul
            kv_store_flows = self.kv_store._kv_get(PATH_PREFIX + '/' + id,
                                                   recurse=True)
            if kv_store_flows is not None:
                for kv_store_flow in kv_store_flows:
                    # Extracting cookie id from the kv store flow details
                    # and deleting each flows
                    flow = json.loads(kv_store_flow['Value'])
                    cookie = flow.keys()[0]
                    del self.kv_store[id + '/' + str(cookie)]
                log.debug("kv-store-flows-cleared-successfully")
            else:
                log.debug("no-flows-found-in-kv-store")
                return

        except Exception as e:
            log.exception("clear-kv-store", e=e)

    def is_reference_found_for_key_value(self, device_id, key, value):
        id = device_id.encode('ascii', 'ignore')
        try:
            # Get all the flows present in the consul
            kv_store_flows = self.kv_store._kv_get(PATH_PREFIX + '/' + id,
                                                   recurse=True)
            if kv_store_flows is not None:
                for kv_store_flow in kv_store_flows:
                    flow = json.loads(kv_store_flow['Value'])
                    cookie = flow.keys()[0]
                    flow_data = flow[cookie]
                    if key in flow_data.keys():
                        # Check if have reference for the Key in the flow
                        # with the given value
                        if flow_data[key] == value:
                            return True
        except Exception as e:
            log.exception("excepting-finding-refernece-for-kv", e=e)

        return False
