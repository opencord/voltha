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
""" Additional definitions not found in OMCI library"""

from enum import Enum


class ReasonCodes(Enum):
    # OMCI Result and reason codes

    Success = 0,            # Command processed successfully
    ProcessingError = 1,    # Command processing error
    NotSupported = 2,       # Command not supported
    ParameterError = 3,     # Parameter error
    UnknownEntity = 4,      # Unknown managed entity
    UnknownInstance = 5,    # Unknown managed entity instance
    DeviceBusy = 6,         # Device busy
    InstanceExists = 7,     # Instance Exists
    AttributeFailure = 9,   # Attribute(s) failed or unknown
