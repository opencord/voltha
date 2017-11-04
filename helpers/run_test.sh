#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)

. $PROG_DIR/colors.sh

TEST=$1; shift
echo -en "TEST: ${WHITE}$TEST${NC} ... "
OUT=$(eval $* 2>&1)
ERR=$?
if [ $ERR -eq 0 ]; then
    echo -e "${GREEN}ok${NC}"
    exit 0
else
    echo -e "${RED}FAILED: $OUT${NC}"
    exit $?
fi
