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

