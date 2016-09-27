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
export PYTHONPATH=$PYTHONPATH:$VOLTHA_BASE/voltha:$VOLTHA_BASE/voltha/core/protos/third_party

# assign DOCKER_HOST_IP to be the main ip address of this host
export DOCKER_HOST_IP=$(python voltha/nethelpers.py)

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

