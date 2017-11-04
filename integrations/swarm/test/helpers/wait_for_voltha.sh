#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)
COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)

. $COMMON_DIR/colors.sh

PREFIX=$1
SLEEP=${2:-3}
RETRY=${3:-60}

echo -en "Waiting for all VOLTHA (${WHITE}$PREFIX${NC}) services to be ready ..."

EXPECTED=$(docker stack services -q $PREFIX | wc -l 2>&1)
if [[ $EXPECTED == Nothing* ]]; then
    echo -e " ${RED}VOLTHA servies not started${NC}"
    exit 1
fi

DONE=0
while [ $RETRY -gt 0 -a $DONE -ne 1 ]; do
    sleep $SLEEP
    echo -n "."
    DONE=1
    SERVICES=$(docker service ls --format '{{.Name}}/{{.Replicas}}' | grep "^$PREFIX")
    if [ $(echo $SERVICES | wc -w) -ne $EXPECTED ]; then
        DONE=0
    else
        for s in $SERVICES; do
            HAVE=$(echo $s | cut -d/ -f2)
            WANT=$(echo $s | cut -d/ -f3)
            if [ $HAVE -ne $WANT ]; then
                DONE=0
                break
            fi
        done
    fi
    RETRY=$(expr $RETRY - 1)
done
if [ $DONE -eq 0 ]; then
    echo -e " ${RED}VOLTHA services not started${NC}"
    exit 1
fi
echo -e " ${GREEN}ok${NC}"
