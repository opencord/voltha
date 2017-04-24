#!/bin/bash
echo "export DOCKER_HOST_IP=$DOCKER_HOST_IP" > /home/voltha/.bashrc
echo "export PYTHONPATH=/cli" >> /home/voltha/.bashrc
echo "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> /home/voltha/.bashrc
echo "export DOCKER_HOST_IP=$DOCKER_HOST_IP" > /home/voltha/.bash_profile
echo "export PYTHONPATH=/cli" >> /home/voltha/.bash_profile
echo "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> /home/voltha/.bash_profile
echo '/cli/cli/main.py -L -C $DOCKER_HOST_IP:8500' >> /home/voltha/.bash_profile
echo "logout" >> /home/voltha/.bash_profile
chown voltha.voltha /home/voltha/.bash_profile
/usr/sbin/sshd -D

