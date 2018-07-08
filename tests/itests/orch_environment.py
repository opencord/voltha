# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from kubernetes import client, config
from common.utils.consulhelpers import get_all_instances_of_service, \
    verify_all_services_healthy

VOLTHA_NAMESPACE = 'voltha'

def get_orch_environment(orch_env):
    if orch_env == 'k8s-single-node':
        return KubernetesEnvironment()
    else:
        return DockerComposeEnvironment()

class OrchestrationEnvironment:

    def verify_all_services_healthy(self, service_name=None,
                                    number_of_expected_services=None):
        raise NotImplementedError('verify_all_services_healthy must be defined')

    def get_all_instances_of_service(self, service_name, port_name=None):
        raise NotImplementedError('get_all_instances_of_service must be defined')

class DockerComposeEnvironment(OrchestrationEnvironment):

    LOCAL_CONSUL = "localhost:8500"

    def verify_all_services_healthy(self, service_name=None,
                                    number_of_expected_services=None):
        return verify_all_services_healthy(self.LOCAL_CONSUL, service_name,
                                           number_of_expected_services)

    def get_all_instances_of_service(self, service_name, port_name=None):
        return get_all_instances_of_service(self.LOCAL_CONSUL, service_name)

class KubernetesEnvironment(OrchestrationEnvironment):

    config.load_kube_config()
    k8s_client = client.CoreV1Api()

    def verify_all_services_healthy(self, service_name=None,
                                    number_of_expected_services=None):

        def check_health(service):
            healthy = True
            if service is None:
                healthy = False
            else:
                pods = self.get_all_pods_for_service(service.metadata.name)
                for pod in pods:
                    if pod.status.phase != 'Running':
                        healthy = False
            return healthy

        if service_name is not None:
            return check_health(self.k8s_client.read_namespaced_service(service_name, VOLTHA_NAMESPACE))

        services = self.k8s_client.list_namespaced_service(VOLTHA_NAMESPACE, watch=False)
        if number_of_expected_services is not None and \
                        len(services.items) != number_of_expected_services:
            return False

        for svc in services.items:
            if not check_health(svc):
                return False

        return True

    def get_all_instances_of_service(self, service_name, port_name=None):
        # Get service ports
        port_num = None
        svc = self.k8s_client.read_namespaced_service(service_name, VOLTHA_NAMESPACE)
        if svc is not None:
            ports = svc.spec.ports
            for port in ports:
                if port.name == port_name:
                    port_num = port.port

        pods = self.get_all_pods_for_service(service_name)
        services = []
        for pod in pods:
            service = {}
            service['ServiceAddress'] = pod.status.pod_ip
            service['ServicePort'] = port_num
            services.append(service)
        return services

    def get_all_pods_for_service(self, service_name):
        '''
        A Service is tied to the Pods that handle it via the Service's spec.selector.app
        property, whose value matches that of the spec.template.metadata.labels.app property
        of the Pods' controller. The controller, in turn, sets each pod's metadata.labels.app
        property to that same value. In Voltha, the 'app' property is set to the service's
        name. This function extracts the value of the service's 'app' selector and then
        searches all pods that have an 'app' label set to the same value.

        :param service_name
        :return: A list of the pods handling service_name
        '''
        pods = []
        svc = self.k8s_client.read_namespaced_service(service_name, VOLTHA_NAMESPACE)
        if svc is not None and 'app' in svc.spec.selector:
            app_label = svc.spec.selector['app']
            ret = self.k8s_client.list_namespaced_pod(VOLTHA_NAMESPACE, watch=False)
            for pod in ret.items:
                labels = pod.metadata.labels
                if 'app' in labels and labels['app'] == app_label:
                    pods.append(pod)
        return pods
