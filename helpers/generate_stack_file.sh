#!/bin/bash

PROG=$(basename $0)
PROG_DIR=$(dirname $0)
TOP_DIR=$(cd $(dirname $PROG_DIR); pwd)

. $PROG_DIR/colors.sh

MANAGER_COUNT=$(docker info -f '{{.Swarm.Managers}}')
docker run -ti -e SWARM_MANAGER_COUNT=$MANAGER_COUNT -v $TOP_DIR:/data opencord/voltha-j2 /data/stacks/voltha-stack.yml.j2
