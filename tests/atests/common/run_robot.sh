#!/bin/bash +x

echo "Run Robot Framework TEST. Log: $1"
cd /home/oleg/cord/incubator/voltha/
source env.sh
robot -d $1 -v LOG_DIR:$1/voltha /home/oleg/VolthaAutoTesting/robot/AutoTesting.robot