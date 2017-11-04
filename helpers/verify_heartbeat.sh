#!/bin/bash

PROG=$(basename $0)
PROG_DIR=$(dirname $0)

. $PROG_DIR/colors.sh

SLEEP=${1:-1}
RETRY=${2:-10}

ID=$(docker ps --filter Name=smoke-test_tools* -q)
if [ -z "$ID" ]; then
    echo -e "${RED}Unable to find tools container${NC}"
    exit 1
fi

echo -n "Verifying headbeat channel in kafka ..."
while [ $RETRY -gt 0 ]; do
    docker exec -ti $ID kafkacat -b 'kafka:9092' -L | grep "voltha.heartbeat" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e " ${GREEN}ok${NC}"
        exit 0
    fi
    echo -n "."
    sleep $SLEEP
    RETRY=$(expr $RETRY - 1)
done
echo -e " ${RED}failed${NC}"
exit 1
