#!/bin/bash

# This script will collect all of the pertinent logs from a voltha
# HA swarm cluster, tar, and bizip them to facilitate sending them
# to the suspected issue owner.

volthaDir="/cord/incubator/voltha"

# Get the list of the other hosts that make up the cluster
hosts=`docker node ls | tail -n +2 | awk '{print $2}' | grep -v "*"`

# Create a temporary directory for temporary storage of all the logs
mkdir ${volthaDir}/log_tmp
pushd ${volthaDir}/log_tmp

# Docker health in general.

echo "Getting docker node ls"
docker node ls > docker_node_ls.log 2>&1
echo "Getting docker service ls"
docker service ls > docker_service_ls.log 2>&1

# Get the list of services to ps each one and get logs for each one.
svcs=`docker service ls | tail -n +2 | awk '{print $2}'`

# Get the PS information 
for i in $svcs
do
	echo "Getting docker service ps $i"
	docker service ps ${i} > docker_service_ps_${i} 2>&1
done

# Get the logs for each service
for i in $svcs
do
	echo "Getting docker service logs $i"
	docker service logs ${i} > docker_service_logs_${i} 2>&1 &
done

patience=10
while [ ! -z "`jobs -p`" ]
do
 echo "*** Waiting on log collection to complete. Outstanding jobs: `jobs -p | wc -l`"
 sleep 10
 patience=`expr $patience - 1`
 if [ $patience -eq 0 ]; then
  echo "Log collection stuck, killing any active collectors"
  for i in `jobs -p`
  do
   kill -s TERM $i
  done
  break
 fi
done

# Get the image list from this host
echo "Getting docker image ls from `hostname`"
docker image ls > docker_image_ls_`hostname` 2>&1
for i in $hosts
do
	echo "Getting docker image ls from $i"
	ssh voltha@$i "docker image ls" > docker_image_ls_$i 2>&1
done


popd
tar cjvf logs.tar.bz2 log_tmp/*
rm -fr log_tmp



