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
from common.utils.dockerhelpers import create_host_config, create_container, start_container, create_networking_config, \
    get_all_running_containers, inspect_container, remove_container

from structlog import get_logger

log = get_logger()

INSTANCE_ID_KEY = 'com.docker.compose.container-number'
INSTANCE_NAME_KEY = 'name'


def check(event):
    return ('from' in event) and\
           ('Actor' in event and 'Attributes' in event['Actor'] and\
                        INSTANCE_ID_KEY in event['Actor']['Attributes']) and\
           ('Actor' in event and 'Attributes' in event['Actor'] and\
                        INSTANCE_NAME_KEY in event['Actor']['Attributes'])

def get_entry(key, dico, mandatory = False, noneval=None):
    if key in dico:
        return dico[key]
    if mandatory:
        raise Exception('Key {} must be in container config'.format(key))
    return noneval

def obtain_network_name(data):
    return data['NetworkSettings']['Networks'].keys()


def create_network_config(network, links):
    if links is None:
        return None
    # Assuming only one network exists....
    return create_networking_config(network[0], { l : l for l in links})


def process_value(value):
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        retval = {}
        for item in value:
            if not isinstance(item, int) and ':' in item:
                item_split = item.split(':')
                retval[item_split[0]] = item_split[1]
            else:
                retval[item] = None
        return retval
    raise Exception('Cannot handle {}'.format(value))

def construct_container_spec(config):
    container_spec = {}
    container_spec['image'] = get_entry('image', config, mandatory=True)
    #TODO need to rewrite command to connect to right service instance
    container_spec['command'] = get_entry('command', config, mandatory=True)
    container_spec['environment'] = get_entry('environment', config, noneval={})
    container_spec['ports'] = get_entry('ports', config)
    container_spec['volumes'] = get_entry('volumes', config)
    return container_spec

def service_shutdown(service, instance_name, config):
    containers = get_all_running_containers()
    for container in containers:
        info = inspect_container(container['Id'])
        envs = info['Config']['Env']
        for env in envs:
            for name in env.split('='):
                if name == instance_name:
                    log.info('Removing container {}'.format(container['Names']))
                    remove_container(container['Id'])

def start_slaves(service, instance_name, instance_id, data, config):
    if service not in config['services']:
        log.debug('Unknown service {}'.format(service))
        return
    for slave in config['services'][service]['slaves']:
        if slave not in config['slaves']:
            log.debug('Unknown slave service {}'.format(slave))
            continue
        network = obtain_network_name(data)
        netcfg = create_network_config(network, get_entry('links', config['slaves'][slave]))
        container_spec = construct_container_spec(config['slaves'][slave])
        container_spec['networking_config'] = netcfg
        if 'volumes' in container_spec:
            container_spec['host_config'] = create_host_config(
                process_value(container_spec['volumes']),
                process_value(container_spec['ports']))
        container_spec['name'] = 'podder_%s_%s' % (slave, instance_id)

        container_spec['environment']['PODDER_MASTER'] = instance_name

        container = create_container(container_spec)
        start_container(container)


def stop_slaves(service, instance_name, instance_id, data, config):
    log.info('Stopping slaves for {}'.format(instance_name))
    if service in config['services']:
        service_shutdown(service, instance_name, config)
    else:
        # handle slave shutdown; restart him
        pass


def handler_start(event, data, config):
    if not check(event):
        log.debug('event {} is invalid'.format(event) )
        return
    service = event['from']
    instance_name = event['Actor']['Attributes'][INSTANCE_NAME_KEY]
    instance_id = event['Actor']['Attributes'][INSTANCE_ID_KEY]
    start_slaves(service, instance_name, instance_id, data, config)

def handler_stop(event, data, config):
    if not check(event):
        log.debug('event {} is invalid'.format(event) )
        return
    service = event['from']
    instance_name = event['Actor']['Attributes'][INSTANCE_NAME_KEY]
    instance_id = event['Actor']['Attributes'][INSTANCE_ID_KEY]
    stop_slaves(service, instance_name, instance_id, data, config)

