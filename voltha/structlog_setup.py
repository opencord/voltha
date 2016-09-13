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
import logging.config
from collections import OrderedDict

import structlog
import sys
import yaml

try:
    from thread import get_ident as _get_ident
except ImportError:
    from dummy_thread import get_ident as _get_ident


DEFAULT_FLUENT_SERVER = 'localhost:24224'


class FluentRenderer(object):
    def __call__(self, logger, name, event_dict):
        # in order to keep structured log data in event_dict to be forwarded as
        # is to the fluent logger, we need to pass it into the logger framework
        # as the first positional argument.
        args = (event_dict, )
        kwargs = {}
        return args, kwargs


class PlainRenderedOrderedDict(OrderedDict):
    """Our special version of OrderedDict that renders into string as a dict,
       to make the log stream output cleaner.
    """
    def __repr__(self, _repr_running={}):
        'od.__repr__() <==> repr(od)'
        call_key = id(self), _get_ident()
        if call_key in _repr_running:
            return '...'
        _repr_running[call_key] = 1
        try:
            if not self:
                return '{}'
            return '{%s}' % ", ".join("%s: %s" % (k, v) for k, v in self.items())
        finally:
            del _repr_running[call_key]


def setup_fluent_logging(args):
    """Setup structlog pipeline and hook it into the fluent sender"""

    # Configure standard logging
    with open('logging.yaml') as fd:
        conf = yaml.load(fd)
    logging.config.dictConfig(conf['logging'])

    processors = [
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        FluentRenderer(),
    ]
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory(),
                        context_class=PlainRenderedOrderedDict,
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
