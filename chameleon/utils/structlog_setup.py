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

"""Setting up proper logging for Voltha"""

import logging
import logging.config
from collections import OrderedDict

import structlog
from structlog.stdlib import BoundLogger, INFO

try:
    from thread import get_ident as _get_ident
except ImportError:
    from dummy_thread import get_ident as _get_ident


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
            return '{%s}' % ", ".join("%s: %s" % (k, v)
                                      for k, v in self.items())
        finally:
            del _repr_running[call_key]


def setup_logging(log_config, instance_id, verbosity_adjust=0, fluentd=None):
    """
    Set up logging such that:
    - The primary logging entry method is structlog
      (see http://structlog.readthedocs.io/en/stable/index.html)
    - By default, the logging backend is Python standard lib logger
    - Alternatively, fluentd can be configured with to be the backend,
      providing direct bridge to a fluent logging agent.
    """

    def add_exc_info_flag_for_exception(_, name, event_dict):
        if name == 'exception':
            event_dict['exc_info'] = True
        return event_dict

    def add_instance_id(_, __, event_dict):
        event_dict['instance_id'] = instance_id
        return event_dict

    # if fluentd is specified, we need to override the config data with
    # its host and port info
    if fluentd is not None:
        fluentd_host = fluentd.split(':')[0].strip()
        fluentd_port = int(fluentd.split(':')[1].strip())

        handlers = log_config.get('handlers', None)
        if isinstance(handlers, dict):
            for _, defs in handlers.iteritems():
                if isinstance(defs, dict):
                    if defs.get('class', '').endswith('FluentHandler'):
                        defs['host'] = fluentd_host
                        defs['port'] = fluentd_port

    # Configure standard logging
    logging.config.dictConfig(log_config)
    logging.root.level -= 10 * verbosity_adjust

    processors = [
        add_exc_info_flag_for_exception,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        add_instance_id,
        FluentRenderer(),
    ]
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory(),
                        context_class=PlainRenderedOrderedDict,
                        wrapper_class=BoundLogger,
                        processors=processors)

    # Mark first line of log
    log = structlog.get_logger()
    log.info("first-line")
    return log
