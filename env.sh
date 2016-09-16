# sourcing this file is needed to make local development and integration testing work

# load local python virtualenv 
. venv/bin/activate


# assign DOCKER_HOST_IP to be the main ip address of this host
export DOCKER_HOST_IP=$(python voltha/nethelpers.py)

