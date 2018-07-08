# Copyright 2017-present Open Networking Foundation
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
"""
Monkey patched json_format to allow best effort decoding of Any fields.
Use the additional flag (strict_any_handling=False) to trigger the
best-effort behavior. Omit the flag, or just use the original json_format
module fot the strict behavior.
"""

from google.protobuf import json_format

class _PatchedPrinter(json_format._Printer):

    def __init__(self, including_default_value_fields=False,
                 preserving_proto_field_name=False,
                 strict_any_handling=False):
        super(_PatchedPrinter, self).__init__(including_default_value_fields,
                                              preserving_proto_field_name)
        self.strict_any_handling = strict_any_handling

    def _BestEffortAnyMessageToJsonObject(self, msg):
        try:
            res = self._AnyMessageToJsonObject(msg)
        except TypeError:
            res = self._RegularMessageToJsonObject(msg, {})
        return res


def MessageToDict(message,
                  including_default_value_fields=False,
                  preserving_proto_field_name=False,
                  strict_any_handling=False):
    """Converts protobuf message to a JSON dictionary.

    Args:
      message: The protocol buffers message instance to serialize.
      including_default_value_fields: If True, singular primitive fields,
          repeated fields, and map fields will always be serialized.  If
          False, only serialize non-empty fields.  Singular message fields
          and oneof fields are not affected by this option.
      preserving_proto_field_name: If True, use the original proto field
          names as defined in the .proto file. If False, convert the field
          names to lowerCamelCase.
      strict_any_handling: If True, converion will error out (like in the
          original method) if an Any field with value for which the Any type
          is not loaded is encountered. If False, the conversion will leave
          the field un-packed, but otherwise will continue.

    Returns:
      A dict representation of the JSON formatted protocol buffer message.
    """
    printer = _PatchedPrinter(including_default_value_fields,
                              preserving_proto_field_name,
                              strict_any_handling=strict_any_handling)
    # pylint: disable=protected-access
    return printer._MessageToJsonObject(message)


def MessageToJson(message,
                  including_default_value_fields=False,
                  preserving_proto_field_name=False,
                  strict_any_handling=False):
  """Converts protobuf message to JSON format.

  Args:
    message: The protocol buffers message instance to serialize.
    including_default_value_fields: If True, singular primitive fields,
        repeated fields, and map fields will always be serialized.  If
        False, only serialize non-empty fields.  Singular message fields
        and oneof fields are not affected by this option.
    preserving_proto_field_name: If True, use the original proto field
        names as defined in the .proto file. If False, convert the field
        names to lowerCamelCase.
    strict_any_handling: If True, converion will error out (like in the
        original method) if an Any field with value for which the Any type
        is not loaded is encountered. If False, the conversion will leave
        the field un-packed, but otherwise will continue.

  Returns:
    A string containing the JSON formatted protocol buffer message.
  """
  printer = _PatchedPrinter(including_default_value_fields,
                            preserving_proto_field_name,
                            strict_any_handling=strict_any_handling)
  return printer.ToJsonString(message)


json_format._WKTJSONMETHODS['google.protobuf.Any'] = [
    '_BestEffortAnyMessageToJsonObject',
    '_ConvertAnyMessage'
]

json_format._Printer._BestEffortAnyMessageToJsonObject = \
    json_format._Printer._AnyMessageToJsonObject
