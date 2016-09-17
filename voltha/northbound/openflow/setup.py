from __future__ import print_function
from setuptools.command.test import test as TestCommand
import io
import os
import sys

import pyofagent

from distutils.core import setup

here = os.path.abspath(os.path.dirname(__file__))


def read(*filenames, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in filenames:
        with io.open(filename, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)

long_description = read('README.md', 'CHANGES.md')


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errcode = pytest.main(self.test_args)
        sys.exit(errcode)


setup(name='pyofagent',
      version=pyofagent.__version__,
      url='notyet',
      license='Apache Software License',
      author='Zsolt Haraszti',
      tests_require=['pytest'],
      install_requires=['hexdump>=3.3',
                        'pcapy'],
      cmdclass={'test': PyTest},
      author_email='zharaszt@ciena.com',
      description='Python-based OpenFlow 1.3 agent',
      long_description=long_description,
      packages=['pyofagent'],
      include_package_data=True,
      platforms='any',
      test_suite='pyofagent.test.test_pyofagent',
      classifiers=[
          'Programming Language :: Python',
          'Development Status :: 4 - Beta',
          'Natural Language :: English',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: OS Independent',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],
      extras_require={'testing': ['pytest']}
      )
