#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)
BASE_DIR=$(cd $PROG_DIR; cd ../../../..; pwd)
COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)

PREFIX=$1

. $COMMON_DIR/colors.sh

echo -n "Query number of Docker Swarm Managers ... "
MANAGER_COUNT=$(docker info --format '{{.Swarm.Managers}}')
echo -e "${GREEN}ok ${WHITE}($MANAGER_COUNT)${NC}"

echo -e "Starting VOLTHA (${WHITE}$PREFIX${NC}) ... "

cat $BASE_DIR/stacks/voltha-stack.yml.j2 | docker run -i \
    -e SWARM_MANAGER_COUNT=$MANAGER_COUNT \
    -e USE_EXTERNAL_NETWORK=voltha_test_net \
    opencord/voltha-j2 - 2>&1 | docker stack deploy -c - $PREFIX 2>&1 | sed -e 's/^/    /g'
ERR=$?
if [ $ERR -ne 0 ]; then
    echo -e "${RED}failed${NC}"
else
    echo -e "${GREEN}ok${NC}"
fi
exit $ERR

