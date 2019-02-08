#
# Copyright 2018 the original author or authors.
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
#
import json
import ast
from collections import namedtuple
import structlog
from enum import Enum

from voltha.core.config.config_backend import ConsulStore
from voltha.core.config.config_backend import EtcdStore
from voltha.registry import registry
from voltha.protos import tech_profile_pb2

# logger
log = structlog.get_logger()

DEFAULT_TECH_PROFILE_TABLE_ID = 64

# Enums used while creating TechProfileInstance
Direction = Enum('Direction', ['UPSTREAM', 'DOWNSTREAM', 'BIDIRECTIONAL'],
                 start=0)
SchedulingPolicy = Enum('SchedulingPolicy',
                        ['WRR', 'StrictPriority', 'Hybrid'], start=0)
AdditionalBW = Enum('AdditionalBW', ['None', 'NA', 'BestEffort', 'Auto'],
                    start=0)
DiscardPolicy = Enum('DiscardPolicy',
                     ['TailDrop', 'WTailDrop', 'RED', 'WRED'], start=0)
InferredAdditionBWIndication = Enum('InferredAdditionBWIndication',
                                    ['None', 'NoneAssured', 'BestEffort'],
                                    start=0)


class InstanceControl(object):
    # Default value constants
    ONU_DEFAULT_INSTANCE = 'multi-instance'
    UNI_DEFAULT_INSTANCE = 'single-instance'
    DEFAULT_NUM_GEM_PORTS = 1
    DEFAULT_GEM_PAYLOAD_SIZE = 'auto'

    def __init__(self, onu=ONU_DEFAULT_INSTANCE,
                 uni=UNI_DEFAULT_INSTANCE,
                 num_gem_ports=DEFAULT_NUM_GEM_PORTS,
                 max_gem_payload_size=DEFAULT_GEM_PAYLOAD_SIZE):
        self.onu = onu
        self.uni = uni
        self.num_gem_ports = num_gem_ports
        self.max_gem_payload_size = max_gem_payload_size


class Scheduler(object):
    # Default value constants
    DEFAULT_ADDITIONAL_BW = 'auto'
    DEFAULT_PRIORITY = 0
    DEFAULT_WEIGHT = 0
    DEFAULT_Q_SCHED_POLICY = 'Hybrid'

    def __init__(self, direction, additional_bw=DEFAULT_ADDITIONAL_BW,
                 priority=DEFAULT_PRIORITY,
                 weight=DEFAULT_WEIGHT,
                 q_sched_policy=DEFAULT_Q_SCHED_POLICY):
        self.direction = direction
        self.additional_bw = additional_bw
        self.priority = priority
        self.weight = weight
        self.q_sched_policy = q_sched_policy


class GemPortAttribute(object):
    # Default value constants
    DEFAULT_AES_ENCRYPTION = 'True'
    DEFAULT_PRIORITY_Q = 0
    DEFAULT_WEIGHT = 0
    DEFAULT_MAX_Q_SIZE = 'auto'
    DEFAULT_DISCARD_POLICY = DiscardPolicy.TailDrop.name

    def __init__(self, pbit_map, discard_config,
                 aes_encryption=DEFAULT_AES_ENCRYPTION,
                 scheduling_policy=SchedulingPolicy.WRR.name,
                 priority_q=DEFAULT_PRIORITY_Q,
                 weight=DEFAULT_WEIGHT,
                 max_q_size=DEFAULT_MAX_Q_SIZE,
                 discard_policy=DiscardPolicy.TailDrop.name):
        self.max_q_size = max_q_size
        self.pbit_map = pbit_map
        self.aes_encryption = aes_encryption
        self.scheduling_policy = scheduling_policy
        self.priority_q = priority_q
        self.weight = weight
        self.discard_policy = discard_policy
        self.discard_config = discard_config


class DiscardConfig(object):
    # Default value constants
    DEFAULT_MIN_THRESHOLD = 0
    DEFAULT_MAX_THRESHOLD = 0
    DEFAULT_MAX_PROBABILITY = 0

    def __init__(self, min_threshold=DEFAULT_MIN_THRESHOLD,
                 max_threshold=DEFAULT_MAX_THRESHOLD,
                 max_probability=DEFAULT_MAX_PROBABILITY):
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.max_probability = max_probability


class TechProfile(object):
    # Constants used in default tech profile
    DEFAULT_TECH_PROFILE_NAME = 'Default_1tcont_1gem_Profile'
    DEFAULT_VERSION = 1.0
    DEFAULT_GEMPORTS_COUNT = 1
    pbits = ['0b11111111']

    # Tech profile path prefix in kv store
    KV_STORE_TECH_PROFILE_PATH_PREFIX = 'service/voltha/technology_profiles'

    # Tech profile path in kv store
    TECH_PROFILE_PATH = '{}/{}'  # <technology>/<table_id>

    # Tech profile instance path in kv store
    # Format: <technology>/<table_id>/<uni_port_name>
    TECH_PROFILE_INSTANCE_PATH = '{}/{}/{}'

    # Tech-Profile JSON String Keys
    NAME = 'name'
    PROFILE_TYPE = 'profile_type'
    VERSION = 'version'
    NUM_GEM_PORTS = 'num_gem_ports'
    INSTANCE_CONTROL = 'instance_control'
    US_SCHEDULER = 'us_scheduler'
    DS_SCHEDULER = 'ds_scheduler'
    UPSTREAM_GEM_PORT_ATTRIBUTE_LIST = 'upstream_gem_port_attribute_list'
    DOWNSTREAM_GEM_PORT_ATTRIBUTE_LIST = 'downstream_gem_port_attribute_list'
    ONU = 'onu'
    UNI = 'uni'
    MAX_GEM_PAYLOAD_SIZE = 'max_gem_payload_size'
    DIRECTION = 'direction'
    ADDITIONAL_BW = 'additional_bw'
    PRIORITY = 'priority'
    Q_SCHED_POLICY = 'q_sched_policy'
    WEIGHT = 'weight'
    PBIT_MAP = 'pbit_map'
    DISCARD_CONFIG = 'discard_config'
    MAX_THRESHOLD = 'max_threshold'
    MIN_THRESHOLD = 'min_threshold'
    MAX_PROBABILITY = 'max_probability'
    DISCARD_POLICY = 'discard_policy'
    PRIORITY_Q = 'priority_q'
    SCHEDULING_POLICY = 'scheduling_policy'
    MAX_Q_SIZE = 'max_q_size'
    AES_ENCRYPTION = 'aes_encryption'

    def __init__(self, resource_mgr):
        try:
            self.args = registry('main').get_args()
            self.resource_mgr = resource_mgr

            if self.args.backend == 'etcd':
                # KV store's IP Address and PORT
                host, port = self.args.etcd.split(':', 1)
                self._kv_store = EtcdStore(
                    host, port, TechProfile.
                        KV_STORE_TECH_PROFILE_PATH_PREFIX)
            elif self.args.backend == 'consul':
                # KV store's IP Address and PORT
                host, port = self.args.consul.split(':', 1)
                self._kv_store = ConsulStore(
                    host, port, TechProfile.
                        KV_STORE_TECH_PROFILE_PATH_PREFIX)

            # self.tech_profile_instance_store = dict()
        except Exception as e:
            log.exception("exception-in-init")
            raise Exception(e)

    class DefaultTechProfile(object):
        def __init__(self, name, **kwargs):
            self.name = name
            self.profile_type = kwargs[TechProfile.PROFILE_TYPE]
            self.version = kwargs[TechProfile.VERSION]
            self.num_gem_ports = kwargs[TechProfile.NUM_GEM_PORTS]
            self.instance_control = kwargs[TechProfile.INSTANCE_CONTROL]
            self.us_scheduler = kwargs[TechProfile.US_SCHEDULER]
            self.ds_scheduler = kwargs[TechProfile.DS_SCHEDULER]
            self.upstream_gem_port_attribute_list = kwargs[
                TechProfile.UPSTREAM_GEM_PORT_ATTRIBUTE_LIST]
            self.downstream_gem_port_attribute_list = kwargs[
                TechProfile.DOWNSTREAM_GEM_PORT_ATTRIBUTE_LIST]

        def to_json(self):
            return json.dumps(self, default=lambda o: o.__dict__,
                              indent=4)

    def get_tp_path(self, table_id, uni_port_name):
        return TechProfile.TECH_PROFILE_INSTANCE_PATH.format(
            self.resource_mgr.technology, table_id, uni_port_name)

    def create_tech_profile_instance(self, table_id, uni_port_name, intf_id):
        tech_profile_instance = None
        try:
            # Get tech profile from kv store
            tech_profile = self._get_tech_profile_from_kv_store(table_id)
            path = self.get_tp_path(table_id, uni_port_name)

            if tech_profile is not None:
                tech_profile = self._get_tech_profile(tech_profile)
                log.debug(
                    "Created-tech-profile-instance-with-values-from-kvstore")
            else:
                # Create a default Tech-Profile.
                # The default profile is a 1 TCONT, 1 GEM port model.
                tech_profile = self._default_tech_profile()
                log.debug(
                    "Created-tech-profile-instance-with-default-values")

            tech_profile_instance = TechProfileInstance(
                uni_port_name, tech_profile, self.resource_mgr, intf_id)
            self._add_tech_profile_instance(path,
                                            tech_profile_instance.to_json())
        except Exception as e:
            log.exception("Create-tech-profile-instance-failed", exception=e)

        return tech_profile_instance

    def get_tech_profile_instance(self, table_id, uni_port_name):
        # path to fetch tech profile instance json from kv store
        path = TechProfile.TECH_PROFILE_INSTANCE_PATH.format(
            self.resource_mgr.technology, table_id, uni_port_name)

        try:
            tech_profile_instance = self._kv_store[path]
            log.debug("Tech-profile-instance-present-in-kvstore", path=path,
                      tech_profile_instance=tech_profile_instance)

            # Parse JSON into an object with attributes corresponding to dict keys.
            tech_profile_instance = json.loads(tech_profile_instance,
                                               object_hook=lambda d:
                                               namedtuple('tech_profile_instance',
                                                          d.keys())(*d.values()))
            log.debug("Tech-profile-instance-after-json-to-object-conversion", path=path,
                      tech_profile_instance=tech_profile_instance)
            return tech_profile_instance
        except BaseException as e:
            log.debug("Tech-profile-instance-not-present-in-kvstore",
                      path=path, tech_profile_instance=None, exception=e)
            return None

    def delete_tech_profile_instance(self, tp_path):

        try:
            del self._kv_store[tp_path]
            log.debug("Delete-tech-profile-instance-success", path=tp_path)
            return True
        except Exception as e:
            log.debug("Delete-tech-profile-instance-failed", path=tp_path,
                      exception=e)
            return False

    def _get_tech_profile_from_kv_store(self, table_id):
        """
        Get tech profile from kv store.

        :param table_id: reference to get tech profile
        :return: tech profile if present in kv store else None
        """
        # get tech profile from kv store
        path = TechProfile.TECH_PROFILE_PATH.format(self.resource_mgr.technology,
                                                    table_id)
        try:
            tech_profile = self._kv_store[path]
            if tech_profile != '':
                log.debug("Get-tech-profile-success", tech_profile=tech_profile)
                return json.loads(tech_profile)
                # return ast.literal_eval(tech_profile)
        except KeyError as e:
            log.info("Get-tech-profile-failed", exception=e)
            return None

    def _default_tech_profile(self):
        # Default tech profile
        upstream_gem_port_attribute_list = list()
        downstream_gem_port_attribute_list = list()
        for pbit in TechProfile.pbits:
            upstream_gem_port_attribute_list.append(
                GemPortAttribute(pbit_map=pbit,
                                 discard_config=DiscardConfig()))
            downstream_gem_port_attribute_list.append(
                GemPortAttribute(pbit_map=pbit,
                                 discard_config=DiscardConfig()))

        return TechProfile.DefaultTechProfile(
            TechProfile.DEFAULT_TECH_PROFILE_NAME,
            profile_type=self.resource_mgr.technology,
            version=TechProfile.DEFAULT_VERSION,
            num_gem_ports=TechProfile.DEFAULT_GEMPORTS_COUNT,
            instance_control=InstanceControl(),
            us_scheduler=Scheduler(direction=Direction.UPSTREAM.name),
            ds_scheduler=Scheduler(direction=Direction.DOWNSTREAM.name),
            upstream_gem_port_attribute_list=upstream_gem_port_attribute_list,
            downstream_gem_port_attribute_list=
            downstream_gem_port_attribute_list)

    @staticmethod
    def _get_tech_profile(tech_profile):
        # Tech profile fetched from kv store
        instance_control = tech_profile[TechProfile.INSTANCE_CONTROL]
        instance_control = InstanceControl(
            onu=instance_control[TechProfile.ONU],
            uni=instance_control[TechProfile.UNI],
            max_gem_payload_size=instance_control[
                TechProfile.MAX_GEM_PAYLOAD_SIZE])

        us_scheduler = tech_profile[TechProfile.US_SCHEDULER]
        us_scheduler = Scheduler(direction=us_scheduler[TechProfile.DIRECTION],
                                 additional_bw=us_scheduler[
                                     TechProfile.ADDITIONAL_BW],
                                 priority=us_scheduler[TechProfile.PRIORITY],
                                 weight=us_scheduler[TechProfile.WEIGHT],
                                 q_sched_policy=us_scheduler[
                                     TechProfile.Q_SCHED_POLICY])
        ds_scheduler = tech_profile[TechProfile.DS_SCHEDULER]
        ds_scheduler = Scheduler(direction=ds_scheduler[TechProfile.DIRECTION],
                                 additional_bw=ds_scheduler[
                                     TechProfile.ADDITIONAL_BW],
                                 priority=ds_scheduler[TechProfile.PRIORITY],
                                 weight=ds_scheduler[TechProfile.WEIGHT],
                                 q_sched_policy=ds_scheduler[
                                     TechProfile.Q_SCHED_POLICY])

        upstream_gem_port_attribute_list = list()
        downstream_gem_port_attribute_list = list()
        us_gemport_attr_list = tech_profile[
            TechProfile.UPSTREAM_GEM_PORT_ATTRIBUTE_LIST]
        for i in range(len(us_gemport_attr_list)):
            upstream_gem_port_attribute_list.append(
                GemPortAttribute(pbit_map=us_gemport_attr_list[i][TechProfile.PBIT_MAP],
                                 discard_config=DiscardConfig(
                                     max_threshold=
                                     us_gemport_attr_list[i][TechProfile.DISCARD_CONFIG][
                                         TechProfile.MAX_THRESHOLD],
                                     min_threshold=
                                     us_gemport_attr_list[i][TechProfile.DISCARD_CONFIG][
                                         TechProfile.MIN_THRESHOLD],
                                     max_probability=
                                     us_gemport_attr_list[i][TechProfile.DISCARD_CONFIG][
                                         TechProfile.MAX_PROBABILITY]),
                                 discard_policy=us_gemport_attr_list[i][
                                     TechProfile.DISCARD_POLICY],
                                 priority_q=us_gemport_attr_list[i][
                                     TechProfile.PRIORITY_Q],
                                 weight=us_gemport_attr_list[i][TechProfile.WEIGHT],
                                 scheduling_policy=us_gemport_attr_list[i][
                                     TechProfile.SCHEDULING_POLICY],
                                 max_q_size=us_gemport_attr_list[i][
                                     TechProfile.MAX_Q_SIZE],
                                 aes_encryption=us_gemport_attr_list[i][
                                     TechProfile.AES_ENCRYPTION]))

        ds_gemport_attr_list = tech_profile[
            TechProfile.DOWNSTREAM_GEM_PORT_ATTRIBUTE_LIST]
        for i in range(len(ds_gemport_attr_list)):
            downstream_gem_port_attribute_list.append(
                GemPortAttribute(pbit_map=ds_gemport_attr_list[i][TechProfile.PBIT_MAP],
                                 discard_config=DiscardConfig(
                                     max_threshold=
                                     ds_gemport_attr_list[i][TechProfile.DISCARD_CONFIG][
                                         TechProfile.MAX_THRESHOLD],
                                     min_threshold=
                                     ds_gemport_attr_list[i][TechProfile.DISCARD_CONFIG][
                                         TechProfile.MIN_THRESHOLD],
                                     max_probability=
                                     ds_gemport_attr_list[i][TechProfile.DISCARD_CONFIG][
                                         TechProfile.MAX_PROBABILITY]),
                                 discard_policy=ds_gemport_attr_list[i][
                                     TechProfile.DISCARD_POLICY],
                                 priority_q=ds_gemport_attr_list[i][
                                     TechProfile.PRIORITY_Q],
                                 weight=ds_gemport_attr_list[i][TechProfile.WEIGHT],
                                 scheduling_policy=ds_gemport_attr_list[i][
                                     TechProfile.SCHEDULING_POLICY],
                                 max_q_size=ds_gemport_attr_list[i][
                                     TechProfile.MAX_Q_SIZE],
                                 aes_encryption=ds_gemport_attr_list[i][
                                     TechProfile.AES_ENCRYPTION]))

        return TechProfile.DefaultTechProfile(
            tech_profile[TechProfile.NAME],
            profile_type=tech_profile[TechProfile.PROFILE_TYPE],
            version=tech_profile[TechProfile.VERSION],
            num_gem_ports=tech_profile[TechProfile.NUM_GEM_PORTS],
            instance_control=instance_control,
            us_scheduler=us_scheduler,
            ds_scheduler=ds_scheduler,
            upstream_gem_port_attribute_list=upstream_gem_port_attribute_list,
            downstream_gem_port_attribute_list=
            downstream_gem_port_attribute_list)

    def _add_tech_profile_instance(self, path, tech_profile_instance):
        """
        Add tech profile to kv store.

        :param path: path to add tech profile
        :param tech_profile_instance: tech profile instance need to be added
        """
        try:
            self._kv_store[path] = str(tech_profile_instance)
            log.debug("Add-tech-profile-instance-success", path=path,
                      tech_profile_instance=tech_profile_instance)
            return True
        except BaseException as e:
            log.exception("Add-tech-profile-instance-failed", path=path,
                          tech_profile_instance=tech_profile_instance,
                          exception=e)
        return False

    @staticmethod
    def get_us_scheduler(tech_profile_instance):
        # upstream scheduler
        us_scheduler = tech_profile_pb2.SchedulerConfig(
            direction=TechProfile.get_parameter(
                'direction', tech_profile_instance.us_scheduler.
                    direction),
            additional_bw=TechProfile.get_parameter(
                'additional_bw', tech_profile_instance.
                    us_scheduler.additional_bw),
            priority=tech_profile_instance.us_scheduler.priority,
            weight=tech_profile_instance.us_scheduler.weight,
            sched_policy=TechProfile.get_parameter(
                'sched_policy', tech_profile_instance.
                    us_scheduler.q_sched_policy))

        return us_scheduler

    @staticmethod
    def get_ds_scheduler(tech_profile_instance):
        ds_scheduler = tech_profile_pb2.SchedulerConfig(
            direction=TechProfile.get_parameter(
                'direction', tech_profile_instance.ds_scheduler.
                    direction),
            additional_bw=TechProfile.get_parameter(
                'additional_bw', tech_profile_instance.
                    ds_scheduler.additional_bw),
            priority=tech_profile_instance.ds_scheduler.priority,
            weight=tech_profile_instance.ds_scheduler.weight,
            sched_policy=TechProfile.get_parameter(
                'sched_policy', tech_profile_instance.ds_scheduler.
                    q_sched_policy))

        return ds_scheduler

    @staticmethod
    def get_traffic_scheds(tech_profile_instance, us_scheduler=None, ds_scheduler=None):
        if us_scheduler is None:
            us_scheduler = TechProfile.get_us_scheduler(tech_profile_instance)
        if ds_scheduler is None:
            ds_scheduler = TechProfile.get_ds_scheduler(tech_profile_instance)

        tconts = [tech_profile_pb2.TrafficScheduler(direction=TechProfile.get_parameter(
            'direction',
            tech_profile_instance.
                us_scheduler.direction),
            alloc_id=tech_profile_instance.
                us_scheduler.alloc_id,
            scheduler=us_scheduler),
            tech_profile_pb2.TrafficScheduler(direction=TechProfile.get_parameter(
                'direction',
                tech_profile_instance.
                    ds_scheduler.direction),
                alloc_id=tech_profile_instance.
                    ds_scheduler.alloc_id,
                scheduler=ds_scheduler)]

        return tconts

    @staticmethod
    def get_traffic_queues(tech_profile_instance):
        gemports = list()
        # Upstream Gemports
        for i in range(len(tech_profile_instance.
                                   upstream_gem_port_attribute_list)):
            gemports.append(tech_profile_pb2.TrafficQueue(
                direction=TechProfile.get_parameter('direction',
                                                    tech_profile_instance.
                                                    us_scheduler.direction),
                gemport_id=tech_profile_instance.
                    upstream_gem_port_attribute_list[i].gemport_id,
                pbit_map=tech_profile_instance.
                    upstream_gem_port_attribute_list[i].pbit_map,
                aes_encryption=ast.literal_eval(tech_profile_instance.
                                                upstream_gem_port_attribute_list[i].aes_encryption),
                sched_policy=TechProfile.get_parameter(
                    'sched_policy', tech_profile_instance.
                        upstream_gem_port_attribute_list[i].
                        scheduling_policy),
                priority=tech_profile_instance.
                    upstream_gem_port_attribute_list[i].priority_q,
                weight=tech_profile_instance.
                    upstream_gem_port_attribute_list[i].weight,
                discard_policy=TechProfile.get_parameter(
                    'discard_policy', tech_profile_instance.
                        upstream_gem_port_attribute_list[i].
                        discard_policy)))

        # Downstream Gemports
        for i in range(len(tech_profile_instance.
                                   downstream_gem_port_attribute_list)):
            gemports.append(tech_profile_pb2.TrafficQueue(
                direction=TechProfile.get_parameter('direction',
                                                    tech_profile_instance.
                                                    ds_scheduler.direction),
                gemport_id=tech_profile_instance.
                    downstream_gem_port_attribute_list[i].gemport_id,
                pbit_map=tech_profile_instance.
                    downstream_gem_port_attribute_list[i].pbit_map,
                aes_encryption=ast.literal_eval(tech_profile_instance.
                                                downstream_gem_port_attribute_list[i].aes_encryption),
                sched_policy=TechProfile.get_parameter(
                    'sched_policy', tech_profile_instance.
                        downstream_gem_port_attribute_list[i].
                        scheduling_policy),
                priority=tech_profile_instance.
                    downstream_gem_port_attribute_list[i].priority_q,
                weight=tech_profile_instance.
                    downstream_gem_port_attribute_list[i].weight,
                discard_policy=TechProfile.get_parameter(
                    'discard_policy', tech_profile_instance.
                        downstream_gem_port_attribute_list[i].
                        discard_policy)))
        return gemports

    @staticmethod
    def get_us_traffic_scheduler(tech_profile_instance):
        us_scheduler = TechProfile.get_us_scheduler(tech_profile_instance)
        return tech_profile_pb2.TrafficScheduler(direction=TechProfile.get_parameter(
            'direction',
            us_scheduler.direction),
            alloc_id=us_scheduler.alloc_id,
            scheduler=us_scheduler)

    @staticmethod
    def get_parameter(param_type, param_value):
        parameter = None
        try:
            if param_type == 'direction':
                for direction in tech_profile_pb2.Direction.keys():
                    if param_value == direction:
                        parameter = direction
            elif param_type == 'discard_policy':
                for discard_policy in tech_profile_pb2.DiscardPolicy.keys():
                    if param_value == discard_policy:
                        parameter = discard_policy
            elif param_type == 'q_sched_policy':
                for sched_policy in tech_profile_pb2.SchedulingPolicy.keys():
                    if param_value == sched_policy:
                        parameter = sched_policy
            elif param_type == 'additional_bw':
                for bw_component in tech_profile_pb2.AdditionalBW.keys():
                    if param_value == bw_component:
                        parameter = bw_component
        except BaseException as e:
            log.exception(exception=e)
        return parameter


class TechProfileInstance(object):
    def __init__(self, subscriber_identifier, tech_profile, resource_mgr,
                 intf_id):
        if tech_profile is not None:
            self.subscriber_identifier = subscriber_identifier

            # Get alloc id and gemport id using resource manager
            alloc_id = resource_mgr.get_resource_id(intf_id,
                                                    'ALLOC_ID',
                                                    1)
            gem_ports = resource_mgr.get_resource_id(intf_id,
                                                     'GEMPORT_ID',
                                                     tech_profile.num_gem_ports)

            gemport_list = list()
            if isinstance(gem_ports, int):
                gemport_list.append(gem_ports)
            elif isinstance(gem_ports, list):
                for gem in gem_ports:
                    gemport_list.append(gem)
            else:
                raise Exception("invalid-type")

            self.us_scheduler = TechProfileInstance.IScheduler(
                alloc_id, tech_profile.us_scheduler)
            self.ds_scheduler = TechProfileInstance.IScheduler(
                alloc_id, tech_profile.ds_scheduler)

            self.upstream_gem_port_attribute_list = list()
            self.downstream_gem_port_attribute_list = list()
            for i in range(tech_profile.num_gem_ports):
                self.upstream_gem_port_attribute_list.append(
                    TechProfileInstance.IGemPortAttribute(
                        gemport_list[i],
                        tech_profile.upstream_gem_port_attribute_list[
                            i]))
                self.downstream_gem_port_attribute_list.append(
                    TechProfileInstance.IGemPortAttribute(
                        gemport_list[i],
                        tech_profile.downstream_gem_port_attribute_list[
                            i]))

    class IScheduler(Scheduler):
        def __init__(self, alloc_id, scheduler):
            super(TechProfileInstance.IScheduler, self).__init__(
                scheduler.direction, scheduler.additional_bw,
                scheduler.priority,
                scheduler.weight, scheduler.q_sched_policy)
            self.alloc_id = alloc_id

    class IGemPortAttribute(GemPortAttribute):
        def __init__(self, gemport_id, gem_port_attribute):
            super(TechProfileInstance.IGemPortAttribute, self).__init__(
                gem_port_attribute.pbit_map, gem_port_attribute.discard_config,
                gem_port_attribute.aes_encryption,
                gem_port_attribute.scheduling_policy,
                gem_port_attribute.priority_q, gem_port_attribute.weight,
                gem_port_attribute.max_q_size,
                gem_port_attribute.discard_policy)
            self.gemport_id = gemport_id

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          indent=4)
