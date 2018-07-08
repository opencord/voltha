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
# HA swarm cluster host and place them in replicated storage.

volthaDir="/cord/incubator/voltha"
hName=`hostname`
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

pushd ${volthaDir}/registry_data/registry_volume/log_tmp

# Get the image list from this host
echo "Getting docker image ls from ${hName}"
docker image ls > docker_image_ls_${hName} 2>&1
# Get the memory info for this host
echo "Getting memory info from ${hName}"
cat /proc/meminfo > meminfo_${hName} 2>&1
# Get the disk info for this host
echo "Getting disk info from ${hName}"
df -h > df_${hName} 2>&1

#
# If too many logs are generated it's not unusual that docker service logs
# hangs and never produces the totality of logs for a service. In order
# to get as much information as possible get the individual container logs
# for each container on each host
#

# Get the container logs for this host 
# Start of cut range
st=`docker ps | head -n 1 | sed -e 's/NAMES.*//' | wc -c`
ed=`expr $st + 100`
containers=`docker ps | tail -n +2 | awk '{print $1}'`
for i in $containers
do
	cont=`docker ps | grep $i | cut -c ${st}-${ed}`
	lNames[$cont]=$cont
	lSizes[$cont]=0
	echo "Getting logs for ${cont} on host ${hName}"
	docker logs $i > "docker_logs_${hName}_${cont}" 2>&1 &
	lPids[$cont]=$!
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
		fsz=`stat --format=%s "docker_logs_${hName}_${i}"`
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


popd
