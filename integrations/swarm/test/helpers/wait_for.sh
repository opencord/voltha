#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)
COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)

. $COMMON_DIR/colors.sh

MSG=$1
CMD=$2
ERR_MSG=$3
SLEEP=$4
RETRY=$5

echo -n "$1 ..."
DONE=0
while [ $RETRY -gt 0 -a $DONE -ne 1 ]; do
    sleep $SLEEP
    echo -n "."
    OUT=$(eval $CMD) 2>&1 
    ERR=$?
    if [ $ERR -eq 0 ]; then
        DONE=1
        break
    fi
    RETRY=$(expr $RETRY - 1)
done
if [ $DONE -eq 0 ]; then
    echo -e " ${RED}${ERR_MSG}${NC}"
    exit 1
fi
echo -e " ${GREEN}ok${NC}"
