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

"""Resource KV store - interface between Resource Manager and backend store."""
import structlog

from voltha.core.config.config_backend import ConsulStore
from voltha.core.config.config_backend import EtcdStore

# KV store uses this prefix to store resource info
PATH_PREFIX = 'service/voltha/resource_manager/{}'


class ResourceKvStore(object):
    """Implements apis to store/get/remove resource in backend store."""

    def __init__(self, technology, device_id, backend, host, port):
        """
        Create ResourceKvStore object.

        Based on backend ('consul' and 'etcd' use the host and port
        to create the respective object.

        :param technology: PON technology
        :param device_id: OLT device id
        :param backend: Type of backend storage (etcd or consul)
        :param host: host ip info for backend storage
        :param port: port for the backend storage
        :raises exception when invalid backend store passed as an argument
        """
        # logger
        self._log = structlog.get_logger()

        path = PATH_PREFIX.format(technology)
        try:
            if backend == 'consul':
                self._kv_store = ConsulStore(host, port, path)
            elif backend == 'etcd':
                self._kv_store = EtcdStore(host, port, path)
            else:
                self._log.error('Invalid-backend')
                raise Exception("Invalid-backend-for-kv-store")
        except Exception as e:
            self._log.exception("exception-in-init")
            raise Exception(e)

    def update_to_kv_store(self, path, resource):
        """
        Update resource.

        :param path: path to update the resource
        :param resource: updated resource
        """
        try:
            self._kv_store[path] = str(resource)
            self._log.debug("Resource-updated-in-kv-store", path=path)
            return True
        except BaseException:
            self._log.exception("Resource-update-in-kv-store-failed",
                                path=path, resource=resource)
        return False

    def get_from_kv_store(self, path):
        """
        Get resource.

        :param path: path to get the resource
        """
        resource = None
        try:
            resource = self._kv_store[path]
            self._log.debug("Got-resource-from-kv-store", path=path)
        except KeyError:
            self._log.info("Resource-not-found-updating-resource",
                           path=path)
        except BaseException:
            self._log.exception("Getting-resource-from-kv-store-failed",
                                path=path)
        return resource

    def remove_from_kv_store(self, path):
        """
        Remove resource.

        :param path: path to remove the resource
        """
        try:
            del self._kv_store[path]
            self._log.debug("Resource-deleted-in-kv-store", path=path)
            return True
        except BaseException:
            self._log.exception("Resource-delete-in-kv-store-failed",
                                path=path)
        return False
