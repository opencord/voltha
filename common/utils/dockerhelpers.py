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
Some docker related convenience functions
"""

import os
from structlog import get_logger

from docker import Client


docker_socket = os.environ.get('DOCKER_SOCK', 'unix://tmp/docker.sock')
log = get_logger()


def get_my_containers_name():
    """
    Return the docker containers name in which this process is running.
    To look up the container name, we use the container ID extracted from the
    $HOSTNAME environment variable (which is set by docker conventions).
    :return: String with the docker container name (or None if any issue is
             encountered)
    """
    my_container_id = os.environ.get('HOSTNAME', None)

    try:
        docker_cli = Client(base_url=docker_socket)
        info = docker_cli.inspect_container(my_container_id)

    except Exception, e:
        log.exception('failed', my_container_id=my_container_id, e=e)
        raise

    name = info['Name'].lstrip('/')

    return name

def create_host_config(volumes, ports):
    try:
        port_bindings = { ports[0] : None }
        binds = ['{0}:{1}'.format(k, v) for k, v in volumes.iteritems()]
        docker_cli = Client(base_url=docker_socket)
        host_config = docker_cli.create_host_config(binds=binds,
                                                    port_bindings=port_bindings)
    except Exception, e:
        log.exception('failed host config creation', volumes, ports, e=e)
        raise

    return host_config


def create_container_network(name, links):
    """
    Creates a container networks based on a set of containers.
    :param name: the network name
    :param links: the set of containers to link
    :return: a network configuration
    """
    try:
        docker_cli = Client(base_url=docker_socket)
        docker_cli.create_network(name)
        networking_config = docker_cli.create_networking_config({
            name : docker_cli.create_endpoint_config(links=links)
        })
    except Exception, e:
        log.exception('failed network creation', name, e=e)
        raise

    return networking_config


def start_container(args):
    """
    Starts a requested container with the appropriate configuration.
    :param args: contains arguments for container creation
        (see https://docker-py.readthedocs.io/en/stable/api/#create_container)
    :return: the containers name
    """
    try:
        docker_cli = Client(base_url=docker_socket)
        container = docker_cli.create_container(**args)
        response = docker_cli.start(container=container.get('Id'))
    except Exception, e:
        log.exception('failed', e=e)
        raise
    return response

