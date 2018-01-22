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
YELLOW='\033[0;33m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

usage() {
    echo >&2 "$PROG: [-d <dir>] [-l <log-dir>] [-h]"
    echo >&2 "  -d <dir>        directory in which the 'compose file directory' is located, defaults to '$(pwd)'"
    echo >&2 "  -l <log-dir>    directory into which fluentd logs will be written"
    echo >&2 "  -c <consul-dir> directory into which consul data is written"
    echo >&2 "  -e              ensure voltha_net is encrypted"
    echo >&2 "  -h              this message"
}

wait_for_service() {
  while true
  do
      COUNT=$(docker service ls | grep $1 | awk '{print $4}')
      if [ ! -z "$COUNT" ]; then
          HAVE=$(echo $COUNT | cut -d/ -f1)
          WANT=$(echo $COUNT | cut -d/ -f2)
          if [ $WANT == $HAVE ]; then
            break
          fi
      fi
      sleep 2
  done
}

ENCRYPT_VNET=""

OPTIND=1
while getopts d:l:c:eh OPT; do
    case "$OPT" in
        d) BASE_DIR="$OPTARG";;
        l) export VOLTHA_LOGS="$OPTARG";;
        c) export CONSUL_ROOT="$OPTARG";;
    	e) ENCRYPT_VNET="--opt encrypted=true";;
        h) usage;
           exit 1;;
        esac
done

# If `REGISTRY` is set, but doesn't end in a `/`, then
# add one
test -z "$REGISTRY" -o "$(echo ${REGISTRY: -1})" == "/" || REGISTRY="$REGISTRY/"
test -z "$REPOSITORY" -o "$(echo ${REPOSITORY: -1})" == "/" || REGISTRY="$REPOSITORY/"
TAG=${TAG:-latest}

# Attempt to count Ready Docker Swarm managers
export SWARM_MANAGER_COUNT=$(docker node ls | grep Ready | egrep '(Leader)|(Reachable)' | wc -l | sed -e 's/ //g')
hostName=$(hostname)

echo -n "[network] voltha-net ... "
if [ $(docker network ls | grep voltha_net | wc -l) -eq 0 ]; then
    OUT=$(docker network create --driver overlay \
        --subnet="172.29.19.0/24" \
        $ENCRYPT_VNET voltha_net 2>&1)
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: $OUT${NC}"
    else
        echo -e "${GREEN}created${NC}"
    fi
else
    # Verify that the current encrypted state is the desired encrypted state
    # and if not, tear down and recreate
    CURRENT=$(docker network inspect --format '{{.Options.encrypted}}' voltha_net | grep -v "<no value>")
    if [ "$ENCRYPT_VNET X" != " X" -a "$CURRENT" != "true" -o "$ENCRYPT_VNET X" == " X" -a "$CURRENT" == "true" ]; then
        echo -en "${YELLOW}delete${NC} ... "
        docker network rm voltha_net > /dev/null || exit 1
        OUT=$(docker network create --driver overlay \
            --subnet="172.29.19.0/24" \
            $ENCRYPT_VNET voltha_net 2>&1)
        if [ $? -ne 0 ]; then
            echo -e "${RED}ERROR: $OUT${NC}"
        else
           echo -e "${GREEN}created${NC}"
        fi
    else
        echo -e "${WHITE}already exists${NC}"
    fi
fi

echo -n "[network] kafka_net ... "
if [ $(docker network ls | grep kafka_net | wc -l) -eq 0 ]; then
    OUT=$(docker network create --driver overlay --opt encrypted kafka_net 2>&1)
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: $OUT${NC}"
    else
        echo -e "${GREEN}created${NC}"
    fi
else
    echo -e "${WHITE}already exists${NC}"
fi

docker stack deploy -c $BASE_DIR/compose/docker-compose-kafka-cluster.yml kafka
docker stack deploy -c $BASE_DIR/compose/docker-compose-consul-cluster.yml consul
echo -n "Waiting for consul to start ... "
wait_for_service consul_consul
echo -e "${GREEN}done${NC}"

echo -n "Waiting for consul leader election ... "
patience=10
while true
do
        leader=`curl -v http://${hostName}:8500/v1/status/leader 2>/dev/null | sed -e 's/"//g'`
        if [ ! -z "$leader" ] ; then
                echo -e "${GREEN}Leader elected is on ${leader}${NC}"
                break
        fi
        sleep 10
        patience=`expr $patience - 1`
        if [ $patience -eq 0 ]; then
                echo -e "${RED}Consul leader election taking too long... aborting${NC}"
                echo "Stopping VOLTHA ... "
                ./voltha-swarm-stop.sh
                exit 1
        fi
done

docker stack deploy -c $BASE_DIR/compose/docker-compose-fluentd-agg-cluster.yml fluentd

echo -n "Waiting for fluentd aggregation services to start ... "
wait_for_service fluentd_fluentdstby
wait_for_service fluentd_fluentdactv
echo -e "${GREEN}done${NC}"
sleep 2


TMP_STACK_FILE=$(mktemp -u)
cat $BASE_DIR/compose/docker-compose-all.yml.j2 2>&1 | docker run -e SWARM_MANAGER_COUNT=$SWARM_MANAGER_COUNT --rm -i ${REGISTRY}${REPOSITORY}voltha-j2:${TAG} - 2>&1 > $TMP_STACK_FILE
docker stack deploy -c $TMP_STACK_FILE voltha
rm -f $TMP_STACK_FILE
