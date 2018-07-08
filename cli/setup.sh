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

while getopts LGC:g:s: option
do
    case "${option}"
    in
	L) LOOKUP_OPT="-L";;
	G) GLOBAL_REQUEST_OPT="-G";;
	C) CONSUL_OPT="-C ${OPTARG}";;
	g) GRPC_OPT="-g ${OPTARG}";;
	s) SIM_OPT="-s ${OPTARG}";;
    esac
done

if [ -z "$CONSUL_OPT" ]
then
    CONSUL_OPT="-C $DOCKER_HOST_IP:8500"
fi

echo "export DOCKER_HOST_IP=$DOCKER_HOST_IP" > /home/voltha/.bashrc
echo "export PYTHONPATH=/cli" >> /home/voltha/.bashrc
echo "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> /home/voltha/.bashrc
echo "export DOCKER_HOST_IP=$DOCKER_HOST_IP" > /home/voltha/.bash_profile
echo "export PYTHONPATH=/cli" >> /home/voltha/.bash_profile
echo "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> /home/voltha/.bash_profile
echo "/cli/cli/main.py $LOOKUP_OPT $GLOBAL_REQUEST_OPT $CONSUL_OPT $GRPC_OPT $SIM_OPT" >> /home/voltha/.bash_profile
echo "logout" >> /home/voltha/.bash_profile
chown voltha.voltha /home/voltha/.bash_profile
/usr/sbin/sshd -D

