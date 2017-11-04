#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)

COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)

. $COMMON_DIR/colors.sh

echo -n "Stopping and removing all stacks ... "
STACKS=$(docker stack ls --format '{{.Name}}')
if [ ! -z "$STACKS" ]; then
    OUT=$(docker stack rm $STACKS 2>&1)
    ERR=$?
    if [ $ERR -ne 0 ]; then
        echo -e "${RED}failed${NC}"
        echo -e "${RED}$OUT${NC}"
        exit $ERR
    fi
fi
echo -e "${GREEN}ok${NC}" 

echo -n "Stopping and removing all services ... "
SERVICES=$(docker service ls --format '{{.Name}}')
if [ ! -z "$SERVICES" ]; then
    OUT=$(docker service rm $SERVICES 2>&1)
    ERR=$?
    if [ $ERR -ne 0 ]; then
        echo -e "${RED}failed${NC}"
        echo -e "${RED}$OUT${NC}"
        exit $ERR
    fi
fi
echo -e "${GREEN}ok${NC}"

# At this point all containers that are part of stacks and services
# should be removed, capture any "swarm" containers that are still 
# running so we can not attempt to stop them as a normal container
echo -n "Stopping and removing all containers ... "
SWARM_IDS=$(mktemp -u)
ALL_IDS=$(mktemp -u)
docker container ps -q --filter label=com.docker.swarm.node.id > $SWARM_IDS
# the file can't be empty else grep won't work
echo $HOSTNAME >> $SWARM_IDS
echo "__END_OF_FILE__" >> $SWARM_IDS
docker container ps -q > $ALL_IDS
CONTAINERS=$(grep -v -f $SWARM_IDS $ALL_IDS)
rm -rf $SWARM_IDS $ALL_IDS
if [ ! -z "$CONTAINERS" ]; then
    OUT=$(docker container rm -f -v $CONTAINERS 2>&1)
    ERR=$?
    if [ $ERR -ne 0 ]; then
        echo -e "${RED}failed${NC}"
        echo -e "${RED}$OUT${NC}"
        exit $ERR
    fi
fi
echo -e "${GREEN}ok${NC}"

exit 0
