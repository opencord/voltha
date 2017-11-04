#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)
COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)
. $COMMON_DIR/colors.sh

PREFIX=$1
SERVICE=$2
COUNT=$3

echo -n "Scale service $SERVICE to $COUNT instances ..."
OUT=$(docker service scale ${PREFIX}_${SERVICE}=$COUNT 2>&1)
ERR=$?
if [ $ERR -ne 0 ]; then
    echo -e "${RED}failed${NC}"
    echo -e "${RED}$OUT${NC}"
else
    echo -e "${GREEN}ok${NC}"
fi
exit $ERR
