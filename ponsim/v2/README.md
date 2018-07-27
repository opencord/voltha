# 1. Overview

The PON simulator was re-written for the purpose of easily integrating it in a cluster environment.

It supports the following deployment configurations:

* In a Kubernetes cluster
* In standalone command line mode (not containerized).

**Please note: Swarm mode is NOT supported by this simulator.**

Here are some differences with the legacy PONSIM implementation:
* The OLT and ONU instances are deployed as independent entities.
* Both OLT and ONU are scalable containers.
* OLT-ONU and VOLTHA-OLT communication is done via GRPC

# 2. PON Simulator Usage

```
Usage of ./ponsim:
  -alarm_freq int
    	Frequency of simulated alarms (in seconds) (default 60)
  -alarm_sim
    	Enable generation of simulated alarms
  -api_type string
    	Type of API used to communicate with devices (PONSIM or BAL) (default "PONSIM")
  -device_type string
    	Type of device to simulate (OLT or ONU) (default "OLT")
  -external_if string
    	External Communication Interface for read/write network traffic (default "eth1")
  -fluentd string
    	Fluentd host address
  -grpc_addr string
    	Address used to establish GRPC server connection
  -grpc_port int
    	Port used to establish GRPC server connection (default 50060)
  -internal_if string
    	Internal Communication Interface for read/write network traffic (default "eth0")
  -name string
    	Name of the PON device (default "PON")
  -no_banner
    	Omit startup banner log lines
  -onus int
    	Number of ONUs to simulate (default 1)
  -parent_addr string
    	Address of OLT to connect to (default "olt")
  -parent_port int
    	Port of OLT to connect to (default 50060)
  -promiscuous
    	Enable promiscuous mode on network interfaces
  -quiet
    	Suppress debug and info logs
  -serial_number string
      Serial number of ONU device (default "PSMO12345678")
  -vcore_endpoint string
    	Voltha core endpoint address (default "vcore")
  -verbose
    	Enable verbose logging
```

# 3. Directory structure

```
./common - Contains utilities used within the project
./core - Contains the main component for handling the OLT/ONU services
./grpc - Contains the GRPC server implementation along with the necessary NBI and SBI handlers
./protos - Contains protobuf files specific to the PON simulator 
./scripts - Miscellaneous scripts required by the PON simulator
```

# 4. Requirements

# Golang Installation

If you plan on running the simulator locally, i.e. not in a container, you will need to first 
install setup Golang on your system.  Install using existing packages for your operating system 
or issue the following commands (Linux).

```
cd /tmp
wget https://storage.googleapis.com/golang/go1.9.3.linux-amd64.tar.gz
tar -C /usr/local -xzf /tmp/go1.9.3.linux-amd64.tar.gz
rm -f /tmp/go1.9.3.linux-amd64.tar.gz
mkdir ~/go
```

Edit your profile (e.g. .bashrc) and add the following configuration

```
export GOROOT=/usr/local/go
export GOPATH=~/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```

# 5. Build the PON simulator

## Container Mode

The PON simulator container can be built by issuing the following command.

```
make ponsim
```

## Standalone Mode

To run the PON simulator in standalone mode, you need to do some manual setups.

### Protos

The required protobuf files are built as part of the docker build process.  If you intend to run 
the simulator in a non-containerized way, you will need to build the protobuf files manually.

```
mkdir -p ponsim/v2/protos
cp voltha/protos/*.proto ponsim/v2/protos
cp voltha/adapters/asfvolt16_olt/protos/*.proto ponsim/v2/protos
cp ponsim/v2/protos/*.proto ponsim/v2/protos

sh ponsim/v2/scripts/build_protos.sh ponsim/v2/protos

```

### PON simulator executable (optional)

You can optionally build the PON simulator and make it available through your GOPATH.

```
go get -u github.com/opencord/voltha/ponsim/v2

go build -o $GOPATH/bin/ponsim $GOPATH/src/github.com/opencord/voltha/ponsim/v2/ponsim.go
``` 


# 6. Run in standalone mode (no container)

## Create the necessary docker networks

```
docker network create -o "com.docker.network.bridge.name"="ponsim_wan" \
    --subnet=172.31.31.0/24 ponsim_wan
    
docker network create -o "com.docker.network.bridge.name"="ponsim_internal" \
    --subnet=172.32.32.0/24 ponsim_internal
```

Allow multicast traffic to flow through the ponsim_wan network

```
echo 8 > /sys/class/net/ponsim_wan/bridge/group_fwd_mask
```

## Start VOLTHA

Edit compose/docker-compose-system-test.yml to specify the communication type to use between
the PON simulator and the voltha service.
 
**--ponsim-comm=grpc**

e.g.
```
...
      "/voltha/voltha/main.py",
      "-v",
      "--consul=${DOCKER_HOST_IP}:8500",
      "--rest-port=8880",
      "--grpc-port=50556",
      "--kafka=@kafka",
      "--instance-id-is-container-name",
      "--interface=eth1",
      "--backend=consul",
      "-v",
      "--ponsim-comm=grpc"
...
```

```
docker-compose -f compose/docker-compose-system-test.yml up -d
docker-compose -f compose/docker-compose-auth-test.yml -p auth up -d
```

## OLT

```
ponsim -device_type OLT \
    -internal_if <network to voltha> \
    -external_if <internal network> \
    -vcore_endpoint <ip of vcore instance> \
    -onus 10
```

Example:

```
# Run as root
sudo su

ponsim -device_type OLT \
    -internal_if ponmgmt \
    -external_if ponsim_internal \
    -vcore_endpoint 172.30.30.3 \
    -onus 10
```


## ONU

```
ponsim -device_type ONU \
    -external_if <network to world> \
    -internal_if <internal network> \
    -grpc_port 50061 \
    -parent_addr localhost
```

Example:

```
# Run as root
sudo su

ponsim -device_type ONU \
    -external_if ponsim_wan \
    -internal_if ponsim_internal \
    -grpc_port 50061 \
    -parent_addr localhost
```

## Create PONSIM adapter

Log into the VOLTHA CLI and provision an OLT instance.

```
ssh -p 5022 voltha@localhost

preprovision_olt -t ponsim_olt -H 172.17.0.1:50060
enable
```

## RG

Run the RG tester

```
docker run --net=ponsim_wan --rm --name RG -it cord/tester bash
```

Execute the EAPOL authentication

```
/sbin/wpa_supplicant -Dwired -ieth0 -c /etc/wpa_supplicant/wpa_supplicant.conf
```


# 7. Run in a Kubernetes cluster

Note: The following instructions are just a reference and may be incomplete.


## Install networking components

### Support multiple network interfaces

Install the CNI Genie package which is required to support multiple network interfaces in a container.

```
kubectl apply -f https://raw.githubusercontent.com/Huawei-PaaS/CNI-Genie/master/conf/1.8/genie.yaml
```

### Configure network bridge for PON simulator

Configure PON management network template (on each host).  

```
# Run as root
sudo su

cat <<EOF >> /etc/cni/net.d/20-pon0.conf
{
    "name": "pon0",
    "type": "bridge",
    "bridge": "pon0",
    "isGateway": true,
    "ipMask": true,
    "ipam": {
      "type": "host-local",
      "subnet": "10.22.0.0/16",
      "routes": [
        { "dst": "0.0.0.0/0" }
      ]
   }
}
EOF
```

## Start Voltha Components

```
cd k8s

kubectl apply -f namespace.yml
kubectl apply -f consul.yml
kubectl apply -f zookeeper.yml
kubectl apply -f kafka.yml
kubectl apply -f envoy_for_consul.yml
kubectl apply -f vcore_for_consul.yml
kubectl apply -f ofagent.yml
kubectl apply -f vcli.yml
kubectl apply -f onos.yml
kubectl apply -f freeradius-config.yml
kubectl apply -f freeradius.yml
```

## Start PONSIM

From the main directory, execute the following command:

```
cd k8s

kubectl apply -f olt.yml

# The ONU configuration will setup a bridge on the host to ensure communication with the RG
kubectl apply -f onu.yml

# Setup bridge to allow multicast traffic (must be done on each host running an ONU)
echo 8 > /sys/class/net/pon0/bridge/group_fwd_mask
```

## Create PONSIM adapter

```
ssh -p 5022 voltha@<ip of cli>

preprovision_olt -t ponsim_olt -H olt:50060
enable
```

## Start RG

```
kubectl apply -f rg.yml

# Enter the RG container
kubectl -n voltha exec <rg container id> -ti bash

# Execute some test (e.g. EAPOL authentication)
wpa_supplicant -i eth0 -Dwired -c /etc/wpa_supplicant/wpa_supplicant.conf

```
