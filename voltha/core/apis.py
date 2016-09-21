#
# Copyright 2016 the original author or authors.
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

"""API definition file"""


class CoreApi(object):
    pass


class Health(CoreApi):

    def get(self):
        """
        Query the health of this Voltha instance.
        ---
        tags:
        - admin
        parameters:
        responses:
          200:
            description: Indicates healthy state
          503:
            description: Overloaded
          500:
            description: Server in faulty state
        """
        return None


class DeviceGroup(CoreApi):
    """
    schemas:
      device_group_summary:
        schema:
          id: DeviceGroup
          properties:
            id:
              type: string
              description: Unique identifier of device group
            assigned_to:
              type: string
              description: Unique instance_id of Voltha instance handling group
            device_count:
              type: int
              description: Number of devices in the device group
    """

    def list(self):
        """
        Return the list of device groups managed by Voltha
        ---
        tags:
        - admin
        parameters:
        responses:
          200:
            description: List of device groups
            schema:
              type: array
              items:
                $ref: '#/definitions/DeviceGroup
        """

