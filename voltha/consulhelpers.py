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

"""
Some consul related convenience functions
"""

from structlog import get_logger
from consul import Consul
from random import randint

log = get_logger()


def get_endpoint_from_consul(consul_endpoint, service_name):
    """Look up, from consul, the service name specified by service-name
    """
    log.debug('Retrieving endpoint {} from consul {}'.format(service_name,
                                                             consul_endpoint))
    host = consul_endpoint.split(':')[0].strip()
    port = int(consul_endpoint.split(':')[1].strip())

    consul = Consul(host=host, port=port)
    _, services = consul.catalog.service(service_name)

    if len(services) == 0:
        raise Exception(
            'Cannot find service {} in consul'.format(service_name))

    # pick a random entry
    # TODO should we prefer local IP addresses? Probably.

    service = services[randint(0, len(services) - 1)]
    endpoint = '{}:{}'.format(service['ServiceAddress'],
                              service['ServicePort'])

    print endpoint
    return endpoint


if __name__ == '__main__':
    get_endpoint_from_consul('10.100.198.220:8500', 'kafka')
