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

from structlog import get_logger
from simplejson import dumps
from google.protobuf.json_format import MessageToJson
from voltha.registry import registry

log = get_logger()


def kafka_send_pb(topic, msg):
    try:
        log.debug('send protobuf to kafka', topic=topic, msg=msg)
        kafka_proxy = registry('kafka_proxy')
        if kafka_proxy and not kafka_proxy.is_faulty():
            log.debug('kafka-proxy-available')
            kafka_proxy.send_message(
                topic,
                dumps(MessageToJson(
                    msg,
                    including_default_value_fields=True)))
        else:
            log.error('kafka-proxy-unavailable')
    except Exception, e:
        log.exception('failed-sending-protobuf', e=e)
