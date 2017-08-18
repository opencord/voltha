#!/bin/bash

voltha_base_dir="/cord/incubator/voltha"
hostName=`hostname`

docker network create --driver overlay --subnet=172.29.19.0/24 --opt encrypted=true voltha_net
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-kafka-cluster.yml kafka
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-consul-cluster.yml consul
echo "Waiting for consul to start"
while true
do
	cs=`docker service ls | grep consul_consul | awk '{print $4}'`
	if [ "$cs" == "3/3" ]; then
		break
	fi
done

echo "Waiting for consul leader election"
patience=10
while true
do
	leader=`curl -v http://${hostName}:8500/v1/status/leader 2>/dev/null | sed -e 's/"//g'`
	if [ ! -z "$leader" ] ; then
		echo "Leader elected is on ${leader}"
		break
	fi
	sleep 10
	patience=`expr $patience - 1`
	if [ $patience -eq 0 ]; then
		echo "Consul leader election taking too long... aborting"
		./voltha-swarm-stop.sh
		exit 1
	fi
done


docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-voltha-swarm.yml vcore
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-ofagent-swarm.yml ofagent
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-envoy-swarm.yml voltha
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-vcli.yml cli
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-chameleon-swarm.yml chameleon
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-netconf-swarm.yml netconf
docker stack deploy -c ${voltha_base_dir}/compose/docker-compose-fluentd-cluster.yml fluentd
docker service create -d --name tools --network voltha_net  --network kafka_net --publish "4022:22" voltha/tools

