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

"""
Some consul related convenience functions
"""

from structlog import get_logger
from consul import Consul
from random import randint

log = get_logger()


def connect_to_consult(consul_endpoint):
    log.debug('getting-service-endpoint', consul=consul_endpoint)

    host = consul_endpoint.split(':')[0].strip()
    port = int(consul_endpoint.split(':')[1].strip())

    return Consul(host=host, port=port)


def verify_all_services_healthy(consul_endpoint, service_name=None,
                                number_of_expected_services=None):
    """
    Verify in consul if any service is healthy
    :param consul_endpoint: a <host>:<port> string
    :param service_name: name of service to check, optional
    :param number_of_expected_services number of services to check for, optional
    :return: true if healthy, false otherwise
    """

    def check_health(service):
        _, serv_health = consul.health.service(service, passing=True)
        return not serv_health == []

    consul = connect_to_consult(consul_endpoint)

    if service_name is not None:
        return check_health(service_name)

    services = get_all_services(consul_endpoint)

    items = services.keys()

    if number_of_expected_services is not None and \
            len(items) != number_of_expected_services:
        return False

    for item in items:
        if not check_health(item):
            return False

    return True


def get_all_services(consul_endpoint):

    log.debug('getting-service-verify-health')

    consul = connect_to_consult(consul_endpoint)
    _, services = consul.catalog.services()

    return services


def get_endpoint_from_consul(consul_endpoint, service_name):
    """Look up, from consul, the service name specified by service-name
    """
    log.debug('getting-service-info', service=service_name)

    consul = connect_to_consult(consul_endpoint)
    _, services = consul.catalog.service(service_name)

    if len(services) == 0:
        raise Exception(
            'Cannot find service {} in consul'.format(service_name))
        os.exit(1)

    # pick a random entry
    # TODO should we prefer local IP addresses? Probably.

    service = services[randint(0, len(services) - 1)]
    endpoint = '{}:{}'.format(service['ServiceAddress'],
                              service['ServicePort'])

    return endpoint


if __name__ == '__main__':
    print get_endpoint_from_consul('10.100.198.220:8500', 'kafka')
