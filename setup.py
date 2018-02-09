#!/usr/bin/env python

import os
from setuptools import setup

# Utility function to read the README file.
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = 'voltha',
    version = '1.3.0',
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
