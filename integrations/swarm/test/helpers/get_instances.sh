#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)
COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)
. $COMMON_DIR/colors.sh

PREFIX=$1
SERVICE=$2

which jq > /dev/null
if [ $? -ne 0 ]; then
    >&2 echo -e "${RED}jq tool required${NC}";
    exit 1
fi


IDS=$( docker service ps --format '{{.ID}}' ${PREFIX}_${SERVICE})
exec docker inspect $IDS | jq -cr '[ .[] | .Spec.Networks[0].Target as $target |  { "id" : .ID, "address" : .NetworksAttachments | .[] | select (.Network.ID == $target ) | .Addresses[0] | gsub("/[0-9]*$"; "") } ]'
