#!/bin/bash
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

# This script will collect all of the pertinent logs from a voltha
# HA swarm cluster, tar, and bizip them to facilitate sending them
# to the suspected issue owner. The replicated storage is used to
# allow all hosts to place the logs in a single place.

volthaDir="/cord/incubator/voltha"
declare -A lNames
declare -A lPids
declare -A lSizes

# Checks if a value is not in an array.
notIn() {
	local e match=$1
	shift
	for e; do [[ "$e" == "$match" ]] && return 1; done
	return 0
}

# Get the list of the other hosts that make up the cluster
hosts=`docker node ls | tail -n +2 | grep -v "*" | grep -v "Down" | awk '{print $2}'`

echo "Collecting logs for hosts: `hostname` ${hosts}"

# Create a temporary directory for temporary storage of all the logs
mkdir ${volthaDir}/registry_data/registry_volume/log_tmp
pushd ${volthaDir}/registry_data/registry_volume/log_tmp

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
	lNames[$i]=$i
	lSizes[$i]=0
	docker service logs ${i} > docker_service_logs_${i} 2>&1 &
	lPids[$i]=$!
done

patience=5
while [ "${#lNames[*]}" -ne 0  ]
do
	echo "*** Waiting on log collection to complete (patience = ${patience}). Outstanding jobs: ${#lNames[*]} (${lNames[@]})"
	sleep 10
	# Check which collectors are done are remove them from the list
	jobs > /dev/null # Don't delete this useless line or the next one will eroniously report a PID
	pids=`jobs -p`
	for i in "${lNames[@]}"
	do
		if notIn "${lPids[$i]}" $pids; then
			unset lPids[$i]
			unset lNames[$i]
			unset lSizes[$i]
		fi
	done
	unset pids
	# Now for all remaining jobs check the file size of the log file for growth
	# reset the timeout if the file is still growing. If no files are still growing
	# then don't touch the timeout.
	for i in "${lNames[@]}"
	do
		fsz=`stat --format=%s "docker_service_logs_${i}"`
		if [ ${lSizes[$i]} -lt $fsz ]; then
			patience=5
			lSizes[$i]=$fsz
		fi
	done
	patience=`expr $patience - 1`
	if [ $patience -eq 0 ]; then
		echo "Log collection stuck, killing any active collectors"
		for i in "${lNames[@]}"
		do
			echo "${i}:${lNames[$i]}:${lSizes[$i]}:${lPids[$i]}"
			kill -s TERM ${lPids[$i]}
		done
		break
	fi
done

# Get the image list from this host
#echo "Getting docker image ls from `hostname`"
#docker image ls > docker_image_ls_`hostname` 2>&1
# Get the memory info for this host
#echo "Getting memory info from `hostname`"
#cat /proc/meminfo > meminfo_`hostname` 2>&1
# Get the disk info for this host
#echo "Getting disk info from `hostname`"
#df -h > df_`hostname` 2>&1

#
# If too many logs are generated it's not unusual that docker service logs
# hangs and never produces the totality of logs for a service. In order
# to get as much information as possible get the individual container logs
# for each container on each host
#

# Get the logs for this host
${volthaDir}/get-host-logs.sh


# Get the logs for the other hosts
for i in $hosts
do
	ssh voltha@$i ${volthaDir}/get-host-logs.sh
done

popd
pushd ${volthaDir}/registry_data/registry_volume
tar cjvf ${volthaDir}/logs.tar`date "+%Y%m%d-%H:%M:%S"`.bz2 log_tmp/*
rm -fr log_tmp
popd



