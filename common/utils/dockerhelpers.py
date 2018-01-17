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
Some docker related convenience functions
"""
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import os
import socket
from structlog import get_logger

from docker import Client, errors


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

def get_all_running_containers():
    try:
        docker_cli = Client(base_url=docker_socket)
        containers = docker_cli.containers()

    except Exception, e:
        log.exception('failed', e=e)
        raise

    return containers

def inspect_container(id):
    try:
        docker_cli = Client(base_url=docker_socket)
        info = docker_cli.inspect_container(id)
    except Exception, e:
        log.exception('failed-inspect-container', id=id, e=e)
        raise

    return info

