
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


#!/usr/bin/env python

import os
from setuptools import setup

# Utility function to read the README file.
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

twisted_deps = ['twisted']
scapy_deps = ['scapy>=2.2.0']
setup(
    name = 'voltha',
    version = '0.0.1',
    author = 'Zsolt Haraszti, Nathan Knuth, Ali Al-Shabibi',
    author_email = 'zharaszt@ciena.com',
    description = ('Virtual Optical Line Terminal (OLT) Hardware Abstraction'),
    license = 'LICENSE.txt',
    keywords = 'volt gpon cord',
    url = 'http://gerrit.opencord.org/voltha',
    packages=['voltha', 'tests'],
    long_description=read('README.md'),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Topic :: System :: Networking',
        'Programming Language :: Python',
        'License :: OSI Approved :: Apache License 2.0',
    ],
    install_requires=[
        'six>1.7.2',
    ],
    extras_require={
        'twisted': twisted_deps,
        'all' : twisted_deps
    },
)
