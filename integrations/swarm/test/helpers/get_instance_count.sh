#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)
COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)
. $COMMON_DIR/colors.sh

PREFIX=$1
SERVICE=$2

OUT=$(docker service ls --format '{{.Name}}/{{.Replicas}}' | grep "^${PREFIX}_${SERVICE}" 2>&1)
ERR=$?
if [ $ERR -ne 0 ]; then
    echo -e $OUT
    exit $ERR
fi

WANT=$(echo $OUT | cut -d/ -f2)
HAVE=$(echo $OUT | cut -d/ -f3)
echo "$WANT/$HAVE"
