#!/bin/bash

set -e

TAG=${TAG:-latest}
STACK_TEMPLATE=${STACK_TEMPLATE:-"voltha-stack.yml.j2"}

start () {

	downloaded=0
	if [ ! -f "$STACK_TEMPLATE" ]; then
		wget https://raw.githubusercontent.com/opencord/voltha/master/compose/voltha-stack.yml.j2
		downloaded=1
	fi

	echo $VOLTHA_LOGS
	TMP_STACK_FILE=$(mktemp -u)
	echo $TMP_STACK_FILE
	SWARM_MANAGER_COUNT=$(docker node ls | grep Ready | egrep "(Leader)|(Reachable)" | wc -l | sed -e "s/ //g")
	cat $STACK_TEMPLATE 2>&1 | docker run -e RADIUS_ROOT=$RADIUS_ROOT -e CONSUL_ROOT=$CONSUL_ROOT -e VOLTHA_LOGS=$VOLTHA_LOGS -e SWARM_MANAGER_COUNT=$SWARM_MANAGER_COUNT --rm -i ${REGISTRY}${REPOSITORY}voltha-j2:${TAG} - 2>&1 > $TMP_STACK_FILE
	docker stack deploy -c $TMP_STACK_FILE voltha
	rm -f $TMP_STACK_FILE

	if [ $downloaded -eq 1 ]; then
		rm -f $STACK_TEMPLATE
	fi
}

stop () {
	docker stack rm voltha
}

case $1 in
    start)
        start
        ;;
    status)
		if [ -z "$(docker stack ls | grep voltha)" ]; then
			echo "Stopped"
		else
			echo "Running"
		fi
		;;
    stop)
        stop
        ;;
    *)
		echo "Usage: $0 {start|stop}" >&2
		exit 1
		;;
esac