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
import os

from docker import Client
from structlog import get_logger

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