#!/bin/bash
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

# Runs VOLTHA using a templatized docker stack file.
# We need to use a templatized file to configure a few things that docker doesn't
# make configurable through variables right now, namely number of replicas and
# volume mounts. This runner script first substites some environment variables
# in to the tempated stack file, then runs that stack file.
#
# Look in the stack file template to see what can be configured through environment
# variables - these variable should be set in the environment that runs this script.

set -e

TAG=${TAG:-latest}
STACK_TEMPLATE=${STACK_TEMPLATE:-"voltha-stack.yml.j2"}

start () {
    SWARM_MANAGER_COUNT=$(docker node ls | grep Ready | egrep "(Leader)|(Reachable)" | wc -l | sed -e "s/ //g")
    if [ $SWARM_MANAGER_COUNT -lt 1 ]; then
        echo "No swarm managers found. Run 'docker swarm init' to create a new manager"
        exit 1
    fi

    downloaded=0
    if [ ! -f "$STACK_TEMPLATE" ]; then
        wget https://raw.githubusercontent.com/opencord/voltha/master/compose/voltha-stack.yml.j2
        downloaded=1
    fi

    TMP_STACK_FILE=$(mktemp -u)

    cat $STACK_TEMPLATE 2>&1 | docker run -e CUSTOM_CLI_LABEL=$CUSTOM_CLI_LABEL -e RADIUS_ROOT=$RADIUS_ROOT -e CONSUL_ROOT=$CONSUL_ROOT -e VOLTHA_LOGS=$VOLTHA_LOGS -e SWARM_MANAGER_COUNT=$SWARM_MANAGER_COUNT -e ONOS_CONFIG=$ONOS_CONFIG --rm -i ${REGISTRY}${REPOSITORY}voltha-j2:${TAG} - 2>&1 > $TMP_STACK_FILE
    docker stack deploy -c $TMP_STACK_FILE voltha

    rm -f $TMP_STACK_FILE

    if [ $downloaded -eq 1 ]; then
        rm -f $STACK_TEMPLATE
    fi
}

stop () {
    docker stack rm voltha
}

status() {
    if [ -z "$(docker stack ls | grep voltha)" ]; then
        echo "Stopped"
        exit
    fi

    STATUS="Running"
    for i in $(docker service ls --format '{{.Name}}/{{.Replicas}}' | grep "^voltha_" | grep -v voltha_config_push); do
        NAME=$(echo $i | cut -d/ -f1)
        HAVE=$(echo $i | cut -d/ -f2)
        WANT=$(echo $i | cut -d/ -f3)
        if [ $HAVE -ne $WANT ]; then
            echo "$NAME not running: $HAVE of $WANT"
            STATUS="Incomplete"
        fi
    done

    echo $STATUS
}

case $1 in
    start)
        start
        ;;
    status)
        status
        ;;
    stop)
        stop
        ;;
    *)
        echo "Usage: $0 {start|status|stop}" >&2
        exit 1
        ;;
esac
