#!/bin/bash
PROG=$(basename $0)
PROG_DIR=$(dirname $0)
COMMON_DIR=$(cd $PROG_DIR; cd ../../../helpers; pwd)

. $COMMON_DIR/colors.sh
echo -n "Verify required Docker version ... "
VERSION=$(docker version -f '{{.Server.Version}}')
if [ $? -ne 0 ]; then
    echo -e "${RED}failed${NC}"
    exit 1
fi

MAJOR=$(echo $VERSION | cut -d. -f1)
MINOR=$(echo $VERSION | cut -d. -f2)
if [ $MAJOR -ne 17 -o $MINOR -lt 6 ]; then
    echo -e "${RED}failed${NC}"
    exit 1
fi
echo -e "${GREEN}ok${NC}"

echo -n "Verifing Docker Swarm Mode is active ... "
MANAGERS=$(docker info -f '{{.Swarm.Managers}}')
if [ $? -ne 0 -o $MANAGERS -eq 0 ]; then 
    echo -e "${RED}failed${NC}"
    exit 1
fi
echo -e "${GREEN}ok${NC}"
exit 0
