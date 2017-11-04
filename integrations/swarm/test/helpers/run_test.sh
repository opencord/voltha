#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)
COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)

. $COMMON_DIR/colors.sh

#VOLUME=$1
#CMD=$2
PREFIX=$1
shift
CMD=$*
echo $VOLUME
ID=$(docker ps -q --filter name=${PREFIX}_testrunner  | head -1)
#SRC=$(echo $VOLUME | cut -d: -f1)
#DST=$(echo $VOLUME | cut -d: -f2)
#docker exec -ti $ID rm -rf $DST
#docker cp $SRC $ID:$DST

docker exec -ti $ID bash -c "cd /voltha; $CMD"
