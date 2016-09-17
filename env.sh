# sourcing this file is needed to make local development and integration testing work
export VOLTHA_BASE=$PWD

# load local python virtualenv 
. venv/bin/activate

# assign DOCKER_HOST_IP to be the main ip address of this host
export DOCKER_HOST_IP=$(python voltha/nethelpers.py)

# to avoid permission issues, create a dir for fluentd logs
mkdir -p /tmp/fluentd

