#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)
COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)
. $COMMON_DIR/colors.sh

PREFIX=$1
SERVICE=$2

docker service ps -q ${PREFIX}_${SERVICE} | wc -l | sed -e 's/ //g'
