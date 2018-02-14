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
from unittest import TestCase, main

from voltha.extensions.omci.omci_cc import *


# NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE
#
# NOTE: This is a placeholder for OpenOMCI unit tests of the OMCI_CC class
#       Initial (worthwhile) tests will be provided in VOL-607. The VOL-607
#       check-in will also likely include the start of a mock ONU device.
#
# NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE


class TestOmciCcExample(TestCase):

    def test_example_1(self):

        self.assertTrue(True)
        self.assertFalse(False)
        self.assertEqual('123', '123')

    def test_example_3(self):

        self.assertTrue(True)
        self.assertFalse(False)
        self.assertEqual('123', '123')


if __name__ == '__main__':
    main()

