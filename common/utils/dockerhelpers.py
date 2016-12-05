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
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import os
import socket
from structlog import get_logger

from docker import Client, errors


docker_socket = os.environ.get('DOCKER_SOCK', 'unix://tmp/docker.sock')
log = get_logger()


def remove_container(id, force=True):
    try:
        docker_cli = Client(base_url=docker_socket)
        containers = docker_cli.remove_container(id, force=force)

    except Exception, e:
        log.exception('failed', e=e)
        raise

    return containers

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
        log.debug('failed: {}'.format(e.message))
        raise

    return info


def create_host_config(volumes, ports):
    try:
        port_bindings = ports
        binds = ['{0}:{1}'.format(k, v) for k, v in volumes.iteritems()]
        docker_cli = Client(base_url=docker_socket)
        host_config = docker_cli.create_host_config(binds=binds,
                                                    port_bindings=port_bindings)
    except Exception, e:
        log.exception('failed host config creation', volumes, ports, e=e)
        raise

    return host_config

def connect_container_to_network(container, net_id, links):
    try:
        docker_cli = Client(base_url=docker_socket)
        docker_cli.connect_container_to_network(container, net_id, links=links)
    except:
        log.exception('Failed to connect container {} to network {}'.format(container, net_id))
        raise

def create_networking_config(name, links):
    """
    Creates a container networks based on a set of containers.
    :param name: the network name
    :param links: the set of containers to link
    :return: a network configuration
    """
    try:
        docker_cli = Client(base_url=docker_socket)
        networking_config = docker_cli.create_networking_config({
            name : docker_cli.create_endpoint_config(links=links)
        })
    except Exception, e:
        log.exception('failed network creation', name, e=e)
        raise

    return networking_config

def stop_container(container, timeout=10):
    try:
        docker_cli = Client(base_url=docker_socket)
        docker_cli.stop(container, timeout=timeout)
    except Exception, e:
        log.exception('failed', e=e)
        raise

def create_container(args):
    try:
        docker_cli = Client(base_url=docker_socket)
        container = docker_cli.create_container(**args)
    except Exception, e:
        log.exception('failed', e=e)
        raise
    return container

def start_container(container):
    """
    Starts a requested container with the appropriate configuration.
    :param args: contains arguments for container creation
        (see https://docker-py.readthedocs.io/en/stable/api/#create_container)
    :return: the containers name
    """
    try:
        docker_cli = Client(base_url=docker_socket)
        response = docker_cli.start(container=container.get('Id'))
    except Exception, e:
        log.exception('failed', e=e)
        raise
    return response

class EventProcessor(object):
    """
    This class handles the api session and allows for it to
    be terminated.
    """
    def __init__(self, threads=1):
        self.client = CustomClient(base_url=docker_socket)
        self.events = self.client.events(decode=True)
        log.info("Starting event processor with {} threads".format(threads))
        self.exec_service = ThreadPoolExecutor(max_workers=threads)

    def stop_listening(self):
        """
        Shuts down the socket.
        :return: None
        """
        if self.events is not None:
            sock = self.client._get_raw_response_socket(self.events.response)
            sock.shutdown(socket.SHUT_RDWR)


    def listen_for_events(self, handlers):
        """
        Listens to the docker event stream and applies the functions
        in the passed handler to each event.

        docker containers can report the following events:

        attach, commit, copy, create, destroy, detach, die,
        exec_create, exec_detach, exec_start, export,
        health_status, kill, oom, pause, rename, resize,
        restart, start, stop, top, unpause, update

        :param handlers: a dict of functions
        :return: None
        """
        if not handlers or len(handlers) == 0:
            raise ValueError("Handlers cannot be empty")

        for event in self.events:
            for k in ['time', 'Time']:
                if k in event:
                    event[k] = datetime.fromtimestamp(event[k])
            log.debug('docker event: {}'.format(event))

            data = {}
            i = get_id(event)
            if i is not None:
                try:
                    if 'from' in event or 'From' in event:
                        data = self.client.inspect_container(i)
                    else:
                        data = self.client.inspect_image(i)
                    data[i] = data
                except errors.NotFound:
                    log.debug('No data for container {}'.format(i))

            status = get_status(event)
            if status in handlers:
                self.exec_service.submit(handlers[get_status(event)], event,
                                         data, handlers['podder_config'])
            else:
                log.debug("No handler for {}; skipping...".format(status))

class CustomGenerator(object):
    """
    This is a custom ugly class that allows for the generator
    to be (kind of) cleanly closed.
    """
    def __init__(self, stream, response, decode):
        self.stream = stream
        self.response = response
        self.decode = decode

    def __iter__(self):
        for item in super(CustomClient, self.stream).\
                _stream_helper(self.response, self.decode):
            yield item

class CustomClient(Client):
    def _stream_helper(self, response, decode=False):
        return CustomGenerator(self, response, decode)

def get_status(event):
    for k in ['status', 'Status']:
        if k in event:
            return event[k]

def get_id(event):
    for k in ['id', 'ID', 'Id']:
        if k in event:
            return event[k]