# Copyright 2017-present Adtran, Inc.
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

test_xml = """
  <data>
    <physical-entities-state xmlns="http://www.adtran.com/ns/yang/adtran-physical-entities">
      <physical-entity>
        <a-string>something</a-string>
      </physical-entity>
    </physical-entities-state>
  </data>
"""

physical_entities_output = """
  <data>
    <physical-entities-state xmlns="http://www.adtran.com/ns/yang/adtran-physical-entities">
      <physical-entity>
        <name>temperature 0/1</name>
        <availability xmlns="http://www.adtran.com/ns/yang/adtran-physical-entity-availability">
          <availability-status/>
        </availability>
        <classification xmlns:adtn-phys-sens="http://www.adtran.com/ns/yang/adtran-physical-sensors">adtn-phys-sens:temperature-sensor-celsius</classification>
        <is-field-replaceable>false</is-field-replaceable>
      </physical-entity>
      <physical-entity>
        <name>transceiver 0/1</name>
        <availability xmlns="http://www.adtran.com/ns/yang/adtran-physical-entity-availability">
          <availability-status/>
        </availability>
        <classification xmlns:adtn-phys-mod-trans="http://www.adtran.com/ns/yang/adtran-physical-module-transceivers">adtn-phys-mod-trans:transceiver</classification>
        <is-field-replaceable>false</is-field-replaceable>
      </physical-entity>
    </physical-entities-state>
  </data>
"""