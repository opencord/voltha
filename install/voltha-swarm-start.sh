
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


#!/bin/bash

voltha_base_dir="/cord/incubator/voltha"

docker network create --driver overlay --subnet=10.0.1.0/24 --opt encrypted=true voltha_net
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-kafka-cluster.yml kafka
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-consul-cluster.yml consul
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-voltha-swarm.yml vcore
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-envoy-swarm.yml voltha
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-vcli.yml cli
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-chameleon-swarm.yml chameleon
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-netconf-swarm.yml netconf
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-fluentd-cluster.yml fluentd
docker service create -d --name tools --network voltha_net  --network kafka_net --publish "4022:22" voltha/tools

