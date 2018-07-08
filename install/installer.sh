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

lBlue='\033[1;34m'
green='\033[0;32m'
orange='\033[0;33m'
NC='\033[0m'
red='\033[0;31m'
yellow='\033[1;33m'
dGrey='\033[1;30m'
lGrey='\033[1;37m'
lCyan='\033[1;36m'
wd=`pwd`


# Clean up any prior executions
rm -fr .keys
rm -f ansible/hosts/cluster
rm -f ansible/host_vars/*

# Source the configuration information
. install.cfg

if [ -z "$hosts" ]; then
	echo -e "${red}No hosts specifed!!${NC}"
	echo -e "${red}Did you forget to update the config file ${yellow}installer.cfg${red}?${NC}"
	exit
fi

if [  "$iUser" == "voltha" ]; then
	echo -e "${yellow}voltha ${red}can't be used as be install user!!!${NC}"
	echo -e "${red}Please delete the ${yellow}voltha ${red}user on the targets and create a different installation user${NC}"
	exit
fi

# Configure barrier file sizes but only if a value was provided in the config file

if [ -v logLimit ]; then
    sed -i -e "/logger_volume_size/s/.*/logger_volume_size: ${logLimit}/" ansible/group_vars/all
fi
if [ -v regLimit ]; then
    sed -i -e "/registry_volume_size/s/.*/registry_volume_size: ${regLimit}/" ansible/group_vars/all
fi
if [ -v consulLimit ]; then
    sed -i -e "/consul_volume_size/s/.*/consul_volume_size: ${consulLimit}/" ansible/group_vars/all
fi

# Create the key directory
mkdir .keys

# Create the host list
echo "[cluster]" > ansible/hosts/cluster

# Silence SSH and avoid prompts
rm -f ~/.ssh/config
echo "Host *" > ~/.ssh/config
echo "	StrictHostKeyChecking no" >> ~/.ssh/config
echo "	UserKnownHostsFile /dev/null" >> ~/.ssh/config

sudo cp ~/.ssh/config /root/.ssh/config

for i in $hosts
do
    # Generate the key for the host
    echo -e "${lBlue}Generating the key-pair for communication with host ${yellow}$i${NC}"
    ssh-keygen -f ./$i -t rsa -N ''
    mv $i .keys

    # Generate the pre-configuration script
    echo -e "${lBlue}Creating the pre-configuration script${NC}"
    head -n +1 BashLoginTarget.sh > bash_login.sh
    echo "" >> bash_login.sh
    echo -n 'key="' >> bash_login.sh
    sed -i -e 's/$/"/' $i.pub
    cat $i.pub >> bash_login.sh
    tail -n +2 BashLoginTarget.sh | grep -v "{{ key }}" >> bash_login.sh
    rm $i.pub

    # Copy the pre-config file to the VM
    echo -e "${lBlue}Transfering pre-configuration script to ${yellow}$i${NC}"
    if [ -d ".test" ]; then
        echo -e "${red}Test mode set!!${lBlue} Using pre-populated ssh key for ${yellow}$i${NC}"
        scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .test/$i bash_login.sh $iUser@$i:.bash_login
    else
        scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no bash_login.sh $iUser@$i:.bash_login
    fi
    rm bash_login.sh

    # Run the pre-config file on the VM
    echo -e "${lBlue}Running the pre-configuration script on ${yellow}$i${NC}"
    if [ -d ".test" ]; then
        echo -e "${red}Test mode set!!${lBlue} Using pre-populated ssh key for ${yellow}$i${NC}"
        ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .test/$i $iUser@$i
    else
        ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $iUser@$i
    fi

    # Configure ansible and ssh for silent operation
    echo -e "${lBlue}Configuring ansible${NC}"
    echo $i >> ansible/hosts/cluster
    echo "ansible_ssh_private_key_file: $wd/.keys/$i" > ansible/host_vars/$i

    # Create the tunnel to the registry to allow pulls from localhost
    echo -e "${lBlue}Creating a secure shell tunnel to the registry for ${yellow}$i${NC}"
    ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .keys/$i -f voltha@$i -R 5000:localhost:5000 -N

done

# Add the dependent software list to the cluster variables
echo -e "${lBlue}Setting up dependent software${NC}"
# Delete any grub updates since the boot disk is almost
# guaranteed not to be the same device as the installer.
mkdir grub_updates
sudo mv deb_files/*grub* grub_updates
# Sort the packages in dependency order to get rid of scary non-errors
# that are issued by ansible.
#echo -e "${lBlue}Dependency sorting dependent software${NC}"
#./sort_packages.sh
#echo "deb_files:" >> ansible/group_vars/all
#for i in `cat sortedDebs.txt`
#do
#echo "  - $i" >> ansible/group_vars/all
#done

# Make sure the ssh keys propagate to all hosts allowing passwordless logins between them
echo -e "${lBlue}Propagating ssh keys${NC}"
cp -r .keys ansible/roles/cluster-host/files

# Install python on all the 3 servers since python is required for
for i in $hosts
do
    echo -e "${lBlue}Installing ${lCyan}Python${lBlue}${NC}"
    scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .keys/$i -r python-deb voltha@$i:.
    ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .keys/$i  voltha@$i "sudo dpkg -i /home/voltha/python-deb/*minimal*"
    ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .keys/$i  voltha@$i sudo dpkg -i -R /home/voltha/python-deb
    ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .keys/$i  voltha@$i rm -fr python-deb

done

if [  "$cluster_framework" == "kubernetes" ]; then

    echo -e "${green}Deploying kubernetes${NC}"

    # Remove previously created inventory if it exists
    cp -rfp kubespray/inventory/sample kubespray/inventory/voltha

    # Adjust kubespray configuration

    # Destination OS
    sed -i -e "/bootstrap_os: none/s/.*/bootstrap_os: ubuntu/" \
        kubespray/inventory/voltha/group_vars/all.yml

    # Subnet used for deployed k8s services
    sed -i -e "/kube_service_addresses: 10.233.0.0\/18/s/.*/kube_service_addresses: $cluster_service_subnet/" \
        kubespray/inventory/voltha/group_vars/k8s-cluster.yml

    # Subnet used for deployed k8s pods
    sed -i -e "/kube_pods_subnet: 10.233.64.0\/18/s/.*/kube_pods_subnet: $cluster_pod_subnet/" \
        kubespray/inventory/voltha/group_vars/k8s-cluster.yml

    # Prevent any downloads from kubespray
    sed -i -e "s/skip_downloads: false/skip_downloads: true/" \
        kubespray/cluster.yml
    sed -i -e "s/- { role: docker, tags: docker }/#&/" \
        kubespray/cluster.yml
    sed -i -e "s/skip_downloads: false/skip_downloads: true/" \
        kubespray/roles/download/defaults/main.yml
    sed -i -e "s/when: ansible_os_family == \"Debian\"/& and skip_downloads == \"false\" /" \
        kubespray/roles/kubernetes/preinstall/tasks/main.yml
    sed -i -e "s/or is_atomic)/& and skip_downloads == \"false\" /" \
        kubespray/roles/kubernetes/preinstall/tasks/main.yml

    # Configure failover parameters
    sed -i -e "s/kube_controller_node_monitor_grace_period: .*/kube_controller_node_monitor_grace_period: 20s/" \
        kubespray/roles/kubernetes/master/defaults/main.yml
    sed -i -e "s/kube_controller_pod_eviction_timeout: .*/kube_controller_pod_eviction_timeout: 30s/" \
        kubespray/roles/kubernetes/master/defaults/main.yml

    # Construct node inventory
    CONFIG_FILE=kubespray/inventory/voltha/hosts.ini python3 \
        kubespray/contrib/inventory_builder/inventory.py $hosts

    # The inventory builder configures 2 masters.
    # Due to non-stable behaviours, force the use of a single master
    cat kubespray/inventory/voltha/hosts.ini \
	| sed -e ':begin;$!N;s/\(\[kube-master\]\)\n/\1/;tbegin;P;D' \
	| sed -e '/\[kube-master\].*/,/\[kube-node\]/{//!d}' \
	| sed -e 's/\(\[kube-master\]\)\(.*\)/\1\n\2\n/' \
	> kubespray/inventory/voltha/hosts.ini.tmp

    mv kubespray/inventory/voltha/hosts.ini.tmp kubespray/inventory/voltha/hosts.ini

    ordered_nodes=`CONFIG_FILE=kubespray/inventory/voltha/hosts.ini python3 \
        kubespray/contrib/inventory_builder/inventory.py print_ips`

    echo "[k8s-master]" > ansible/hosts/k8s-master

    mkdir -p kubespray/inventory/voltha/host_vars

    ctr=1
    for i in $ordered_nodes
    do
        echo -e "${lBlue}Adding SSH keys to kubespray ansible${NC}"
        echo "ansible_ssh_private_key_file: $wd/.keys/$i" > kubespray/inventory/voltha/host_vars/node$ctr

        if [ $ctr -eq 1 ]; then
            echo  $i >> ansible/hosts/k8s-master
        fi
        ctr=$((ctr + 1))
    done

    # Prepare Voltha
    # ... Prepares environment and copies all required container images
    # ... including the ones needed by kubespray
    cp ansible/ansible.cfg .ansible.cfg
    ansible-playbook -v ansible/voltha-k8s.yml -i ansible/hosts/cluster -e 'config_voltha=true'

    # Deploy kubernetes
    ANSIBLE_CONFIG=kubespray/ansible.cfg ansible-playbook -v -b \
        --become-method=sudo --become-user root -u voltha \
        -i kubespray/inventory/voltha/hosts.ini kubespray/cluster.yml

    # Now all 3 servers need to be rebooted because of software installs.
    # Reboot them and wait patiently until they all come back.
    # Note this destroys the registry tunnel wich is no longer needed.
    hList=""
    for i in $hosts
    do
        echo -e "${lBlue}Rebooting cluster hosts${NC}"
        ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .keys/$i  voltha@$i sudo telinit 6
        hList="$i $hList"
    done

    # Give the hosts time to shut down so that pings stop working or the
    # script just falls through the next loop and the rest fails.
    echo -e "${lBlue}Waiting for shutdown${NC}"
    sleep 5


    while [ ! -z "$hList" ];
    do
        # Attempt to ping the VMs on the list one by one.
        echo -e "${lBlue}Waiting for hosts to reboot ${yellow}$hList${NC}"
        for i in $hList
        do
            ping -q -c 1 $i > /dev/null 2>&1
            ret=$?
            if [ $ret -eq 0 ]; then
                ipExpr=`echo $i | sed -e "s/\./[.]/g"`
                hList=`echo $hList | sed -e "s/$ipExpr//" | sed -e "s/^ //" | sed -e "s/ $//"`
            fi
        done

    done
    
    # Wait for kubernetes to settle after reboot
    k8sIsUp="no"
    while [ "$k8sIsUp" == "no" ];
    do
        # Attempt to ping the VMs on the list one by one.
        echo -e "${lBlue}Waiting for kubernetes to settle${NC}"
        for i in $hosts
        do
            nc -vz $i 6443 > /dev/null 2>&1
            ret=$?
            if [ $ret -eq 0 ]; then
                k8sIsUp="yes"
                break
            fi
            sleep 1
        done
    done
    echo -e "${lBlue}Kubernetes is up and running${NC}"

    # Deploy Voltha
    ansible-playbook -v ansible/voltha-k8s.yml -i ansible/hosts/k8s-master -e 'deploy_voltha=true'

else
    # Legacy swarm instructions

    # Create the daemon.json file for the swarm
    echo "{" > daemon.json
    echo -n '  "insecure-registries" : [' >> daemon.json
    first=""
    for i in .keys/*
    do
        if [ -z "$first" ]; then
            echo -n '"'`basename $i`':5001"' >> daemon.json
            first="not"
        else
            echo -n ' , "'`basename $i`':5001"' >> daemon.json
        fi
    done
    echo "]" >> daemon.json
    echo "}" >> daemon.json
    unset first

    # Running ansible
    echo -e "${lBlue}Running ansible${NC}"
    cp ansible/ansible.cfg .ansible.cfg
    ansible-playbook ansible/voltha.yml -i ansible/hosts/cluster

    # Now all 3 servers need to be rebooted because of software installs.
    # Reboot them and wait patiently until they all come back.
    # Note this destroys the registry tunnel wich is no longer needed.
    hList=""
    for i in $hosts
    do
        echo -e "${lBlue}Rebooting cluster hosts${NC}"
        ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .keys/$i  voltha@$i sudo telinit 6
        hList="$i $hList"
    done

    # Give the hosts time to shut down so that pings stop working or the
    # script just falls through the next loop and the rest fails.
    echo -e "${lBlue}Waiting for shutdown${NC}"
    sleep 5


    while [ ! -z "$hList" ];
    do
        # Attempt to ping the VMs on the list one by one.
        echo -e "${lBlue}Waiting for hosts to reboot ${yellow}$hList${NC}"
        for i in $hList
        do
            ping -q -c 1 $i > /dev/null 2>&1
            ret=$?
            if [ $ret -eq 0 ]; then
                ipExpr=`echo $i | sed -e "s/\./[.]/g"`
                hList=`echo $hList | sed -e "s/$ipExpr//" | sed -e "s/^ //" | sed -e "s/ $//"`
            fi
        done

    done

    # Now initialize the the docker swarm cluster with managers.
    # The first server needs to be the primary swarm manager
    # the other nodes are backup mangers that join the swarm.
    # In the future, worker nodes will likely be added.

    echo "[swarm-master]" > ansible/hosts/swarm-master
    echo "[swarm-master-backup]" > ansible/hosts/swarm-master-backup

    ctr=1
    for i in $hosts
    do
            if [ $ctr -eq 1 ]; then
                    echo  $i >> ansible/hosts/swarm-master
            echo "swarm_master_addr: \"$i\"" >> ansible/group_vars/all
            ctr=0
            else
                    echo  $i >> ansible/hosts/swarm-master-backup
            fi
    done
    ansible-playbook ansible/swarm.yml -i ansible/hosts/swarm-master
    ansible-playbook ansible/swarm.yml -i ansible/hosts/swarm-master-backup
    ansible-playbook ansible/voltha.yml -i ansible/hosts/swarm-master

fi
