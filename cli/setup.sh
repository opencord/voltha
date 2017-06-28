#!/bin/bash

while getopts LC:g:s: option
do
    case "${option}"
    in
	L) LOOKUP_OPT="-L";;
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
echo "/cli/cli/main.py $LOOKUP_OPT $CONSUL_OPT $GRPC_OPT $SIM_OPT" >> /home/voltha/.bash_profile
echo "logout" >> /home/voltha/.bash_profile
chown voltha.voltha /home/voltha/.bash_profile
/usr/sbin/sshd -D

