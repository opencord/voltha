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
constants
"""


class UriConst:
    base_uri = '/redfish/v1'
    chassis_uri = '/Chassis/'
    systems_uri = '/Systems/'
    update_uri = '/UpdateService/'
    ethernet_uri = '/EthernetSwitches/'
    HTTPS = 'https://'


class RestConst:
    GET = 'GET'
    PUT = 'PUT'
    PATCH = 'PATCH'
    POST = 'POST'
    DELETE = 'DELETE'


class Defaults:
    reset_type = 'GracefulRestart'
    health_check_interval = 60
    redfish_port = ':8888'
