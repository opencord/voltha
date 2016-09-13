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

"""Setting up proper logging for Voltha"""

import logging
import structlog
import sys

from fluent import sender
from structlog import _frames


DEFAULT_FLUENT_SERVER = 'localhost:24224'


'''
class FluentLoggerFactory(object):

    def __init__(self, tag, server=DEFAULT_FLUENT_SERVER, additional_ignores=None):
        self.host = server.split(':')[0]
        self.port = int(server.split(':')[1])
        self.emitter = sender.FluentSender(tag=tag, host=self.host, port=self.port)
        self._ignore = additional_ignores

    def __call__(self, name=None):
        if name is not None:
            return logging.getLogger(name)
        else:
            _, name = _frames._find_first_app_frame_and_name(self._ignore)
            return logging.getLogger(name)
'''


class FluentRenderer(object):
    def __call__(self, logger, name, event_dict):
        args = ()
        kwargs = event_dict
        return args, kwargs


def setup_fluent_logging(args):
    """Setup structlog pipeline and hook it into the fluent sender"""

    # Configure standard logging
    DATEFMT = '%Y%m%dT%H%M%S'
    FORMAT = '%(asctime)-11s.%(msecs)03d %(levelname)-8s %(msg)s'
    level = logging.DEBUG if args.verbose else (logging.WARN if args.quiet else logging.INFO)
    logging.basicConfig(stream=sys.stdout, level=level, format=FORMAT, datefmt=DATEFMT)

    processors = [
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        FluentRenderer()
        #structlog.processors.KeyValueRenderer(),  # structlog.processorsJSONRenderer(),
    ]
    # structlog.configure(logger_factory=FluentLoggerFactory(args.fluent_server),
    #                     processors=processors)
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory(),
                        processors=processors)


def setup_standard_logging(args):
    """Setup structlog pipeline and hook it into the standard logging framework of Python"""

    # Configure standard logging
    DATEFMT = '%Y%m%dT%H%M%S'
    FORMAT = '%(asctime)-11s.%(msecs)03d %(levelname)-8s %(msg)s'
    level = logging.DEBUG if args.verbose else (logging.WARN if args.quiet else logging.INFO)
    logging.basicConfig(stream=sys.stdout, level=level, format=FORMAT, datefmt=DATEFMT)

    # Hook up structlog to standard logging
    processors = [
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.KeyValueRenderer(),  # structlog.processorsJSONRenderer(),

    ]
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory(), processors=processors)


def setup_logging(args):
    """
    Set up logging such that:
    - The primary logging entry method is structlog (see http://structlog.readthedocs.io/en/stable/index.html)
    - By default, the logging backend is Python standard lib logger
    - Alternatively, fluentd can be configured with to be the backend, providing direct
      bridge to a fluent logging agent.
    """

    if args.enable_fluent:
        setup_fluent_logging(args)
    else:
        setup_standard_logging(args)

    # Mark first line of log
    log = structlog.get_logger()
    log.info("first-line")
    return log
