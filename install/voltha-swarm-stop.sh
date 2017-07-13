#!/bin/bash

docker service rm chameleon_chameleon
docker service rm netconf_netconf
docker service rm cli_cli
docker service rm voltha_voltha
docker service rm consul_consul
docker service rm kafka_kafka
docker service rm kafka_zk1
docker service rm kafka_zk2
docker service rm kafka_zk3
docker service rm tools
docker network rm voltha_net
docker network rm kafka_net
docker network rm consul_net
