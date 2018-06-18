#!/bin/bash +x

SRC_DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VOLTHA_DIR="$SRC_DIR/../../.."

echo "Run Robot Framework TEST. Log: $1"
cd $VOLTHA_DIR
source env.sh
robot -d $1 -v LOG_DIR:$1/voltha ./tests/atests/robot/auto_testing.robot