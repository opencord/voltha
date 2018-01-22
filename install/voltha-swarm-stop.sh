#!/bin/bash

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

PROG=$(basename $0)
BASE_DIR=$(pwd)

GREEN='\033[32;1m'
RED='\033[0;31m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

SERVICES=""
STACKS="consul kafka fluentd voltha"
NETWORKS="voltha_net kafka_net"

usage() {
    echo >&2 "$PROG: [-d <dir>] [-l <log-dir>] [-h]"
    echo >&2 "  -z              zero out the consul fluentd data"
    echo >&2 "  -l <log-dir>    directory from which fluentd logs will be removed"
    echo >&2 "  -c <consul-dir> directory from which consul data is removed"
    echo >&2 "  -h              this message"
}

VOLUME_CLEANUP=0

OPTIND=1
while getopts d:l:c:zh OPT; do
    case "$OPT" in
        z) VOLUME_CLEANUP=1;;
        c) export CONSUL_ROOT="$OPTARG";;
        l) export VOLTHA_LOGS="$OPTARG";;
        h) usage;
           exit 1;;
        esac
done

for s in $SERVICES; do
    echo -n "[service] $s ... "
    if [ $(docker service ls | grep $s | wc -l) -ne 0 ]; then
        OUT=$(docker service rm $s 2>&1)
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}removed${NC}"
        else
            echo -e "${RED}ERROR: $OUT${NC}"
        fi
    else
        echo -e "${WHITE}not running${NC}"
    fi
done

for s in $STACKS; do
    echo -n "[stack] $s ... "
    if [ $(docker stack ls | grep $s | wc -l) -ne 0 ]; then
        OUT=$(docker stack rm $s 2>&1)
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}removed${NC}"
        else
            echo -e "${RED}ERROR: $OUT${NC}"
        fi
    else
        echo -e "${WHITE}not running${NC}"
    fi
done

for n in $NETWORKS; do
    echo -n "[network] $n ... "
    if [ $(docker network ls | grep $n | wc -l) -ne 0 ]; then
        OUT=$(docker network rm $n 2>&1)
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}removed${NC}"
        else
            echo -e "${RED}ERROR: $OUT${NC}"
        fi
    else
        echo -e "${WHITE}not running${NC}"
    fi
done

# Attempt to count Ready Docker Swarm managers
SWARM_MANAGER_COUNT=$(docker node ls | grep Ready | egrep '(Leader)|(Reachable)' | wc -l)
echo -n "[cleanup] consul and fluentd ... "
if [ $VOLUME_CLEANUP -ne 0 ]; then
    RUNNING=$(docker service ps volume_cleanup 2> /dev/null | wc -l)
    if [ $RUNNING -ne 0 ]; then
        docker service rm volume_cleanup > /dev/null
    fi
    docker service create --detach=true --restart-condition=none \
    --mode=global --name=volume_cleanup \
    --mount=type=bind,src=${CONSUL_ROOT:-/cord/incubator/voltha/consul}/data,dst=/consul/data \
    --mount=type=bind,src=${CONSUL_ROOT:-/cord/incubator/voltha/consul}/config,dst=/consul/config \
    --mount=type=bind,src=${VOLTHA_LOGS:-/var/log/voltha/logging_volume},dst=/fluentd/log \
    alpine:latest \
    ash -c 'rm -rf /consul/data/* /consul/config/* /fluentd/log/*' > /dev/null

    RETRY=10
    while [ $RETRY -ge 0 ]; do
        COMPLETE=$(docker service ps --filter 'desired-state=Shutdown' --format '{{.DesiredState}}' volume_cleanup | wc -l)
        ERRORS=$(docker service ps --format '{{.Error}}' volume_cleanup  | grep -v "^$" | wc -l)
        if [ $COMPLETE -eq $SWARM_MANAGER_COUNT ]; then
           if [ $ERRORS -eq 0 ]; then
               echo -e "${GREEN}data removed${NC}"
               docker service rm volume_cleanup > /dev/null
               break
           else
               echo -e "${RED}ERROR: $(docker service ps --format '{{.Error}}' volume_cleanup | awk '{printf("%s ", $0)}')${NC}"
               exit 1
           fi

        fi
        sleep 5
        RETRY=$(expr $RETRY - 1)
    done
else
   echo -e "${WHITE}skipped${NC}" 
fi
