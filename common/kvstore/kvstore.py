# Copyright 2018-present Open Networking Foundation
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

from common.kvstore.consul_client import ConsulClient
from common.kvstore.etcd_client import EtcdClient

def create_kv_client(kv_store, host, port):
    '''
    Factory for creating a client interface to a KV store

    :param kv_store: Specify either 'etcd' or 'consul'
    :param host: Name or IP address of host serving the KV store
    :param port: Port number (integer) of the KV service
    :return: Reference to newly created client interface
    '''
    if kv_store == 'etcd':
        return EtcdClient(host, port)
    elif kv_store == 'consul':
        return ConsulClient(host, port)
    return None
