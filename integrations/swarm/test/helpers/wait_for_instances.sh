#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)
COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)

. $COMMON_DIR/colors.sh

PREFIX=$1
SERVICE=$2
COUNT=$3
SLEEP=${4:-3}
RETRY=${5:-60}

MSG="Waiting for all VOLTHA (${WHITE}$PREFIX${NC}) service instances (${WHITE}$COUNT${NC}) to be ready"
ERR_MSG="${RED}VOLTHA servies not started${NC}"
CMD='test $(docker service ls --filter Name='${PREFIX}_${SERVICE}' --format '{{.Replicas}}' | cut -d/ -f1) -eq '$COUNT
$COMMON_DIR/wait_for.sh "$MSG" "$CMD" "$ERR_MSG" $SLEEP $RETRY
