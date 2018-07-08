# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# sourcing this file is needed to make local development and integration testing work
export VOLTHA_BASE=$PWD

# load local python virtualenv if exists, otherwise create it
VENVDIR="venv-$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ ! -e "$VENVDIR/.built" ]; then
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "Initializing OS-appropriate virtual env."
    echo "This will take a few minutes."
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    make venv
fi
. $VENVDIR/bin/activate

# add top-level voltha dir to pythonpath
export PYTHONPATH=$VOLTHA_BASE/$VENVDIR/lib/python2.7/site-packages:$PYTHONPATH:$VOLTHA_BASE:$VOLTHA_BASE/voltha/protos/third_party

# assign DOCKER_HOST_IP to be the main ip address of this host
export DOCKER_HOST_IP=$(python common/utils/nethelpers.py)

# to avoid permission issues, create a dir for fluentd logs
# of if it exists make sure we can write to it
mkdir -p /tmp/fluentd
if ! touch /tmp/fluentd/.check_write_permission; then
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "You don't have write privileges for the log directory"
    echo "/tmp/fluentd. This will cause issues when running the"
    echo "fluentd container with docker-compose. We suggest you"
    echo "fox your write permission before proceeding."
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
else
    rm -f /tmp/fluentd/.check_write_permission
fi

