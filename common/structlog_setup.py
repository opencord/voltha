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

import structlog


def setup_logging(log_config, instance_id,
                  verbosity_adjust=0, cache_on_use=True):
    """
    Set up logging such that:
    - The primary logging entry method is structlog
      (see http://structlog.readthedocs.io/en/stable/index.html)
    - Optionally cache the logger on first use
    :return: structured logger
    """

    def add_instance_id(_, __, event_dict):
        event_dict['instance_id'] = instance_id
        return event_dict

    # Configure standard logging
    logging.config.dictConfig(log_config)
    logging.root.level -= 10 * verbosity_adjust

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            add_instance_id,
            structlog.processors.UnicodeEncoder(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=cache_on_use,
    )

    # Mark first line of log
    log = structlog.get_logger()
    log.info("first-log-line, logging level %d" % logging.root.level)
    return log


def update_logging(instance_id, vcore_id, cache_on_use=True):
    """
    Add the vcore id to the structured logger
    :param vcore_id:  The assigned vcore id
    :return: structured logger
    """

    def add_instance_id(_, __, event_dict):
        event_dict['instance_id'] = instance_id
        return event_dict

    def add_vcore_id(_, __, event_dict):
        event_dict['vcore_id'] = vcore_id
        return event_dict

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            add_instance_id,
            add_vcore_id,
            structlog.processors.UnicodeEncoder(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=cache_on_use,
    )

    # Mark first line of log
    log = structlog.get_logger()
    log.info("updated-logger")
    return log
