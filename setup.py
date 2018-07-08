#!/usr/bin/env python
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

import os
from setuptools import setup

# Utility function to read the README file.
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = 'voltha',
    version = '2.0.0-dev',
    author = 'Open Networking Foundation, et al',
    author_email = 'info@opennetworking.org',
    description = ('Virtual Optical Line Terminal (OLT) Hardware Abstraction'),
    license = 'Apache License 2.0',
    keywords = 'volt gpon cord',
    url = 'https://gerrit.opencord.org/#/q/project:voltha',
    packages=['voltha', 'tests'],
    long_description=read('README.md'),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Topic :: System :: Networking',
        'Programming Language :: Python',
        'License :: OSI Approved :: Apache License 2.0',
    ],
)
