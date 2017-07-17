#!/bin/bash

docker service rm chameleon_chameleon
docker service rm netconf_netconf
docker service rm cli_cli
docker service rm voltha_voltha
docker service rm vcore_vcore
docker service rm tools
docker stack rm consul
docker stack rm kafka
docker network rm voltha_net
