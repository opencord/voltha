# How to Build VOLTHA using only Docker

The standard (original) build environment for VOLTHA required the installation
of many support tools or a custom `Vagrant` VM with those same support tools
installed on that VM.

This build guide walks through a VOLTHA build on a system that only support
Docker. If after building VOLTHA, it is desired to run VOLTHA you will need
a version of Docker that supports Swarm Mode or `docker-compose`. It is
recommended that you use the latest stable version of `docker`.

## Building

### Prerequisites

* git - in order to clone the VOLTHA source, not required if you already have
the source or can obtain it via a different mechanism.
* make - standard build utility
* docker - version `17.06.0-ce` or later recommended, the latest stable
version preferred.

### Git Clone source

```bash
git clone http://gerrit.opencord.org/voltha
```

### Build VOLTHA

```bash
cd voltha # if you are not alread in the voltha directory
VOLTHA_BUILD=docker make build
```

The build can take a little while, so feel free to get a cup of coffee, go for
a short walk, or otherwise rest your mind. A build on a clean Ubuntu VM takes
about 30 minutes. The actual time for a build depends on available network
bandwidth and CPU speed.

## Running VOLTHA

### Running VOLTHA

VOLTHA runs as a Docker Swarm Stack. Thus, to run VOLTHA you should have
initialized your Docker Swarm using
```bash
docker swarm init
```

After the swarm has been initialized VOLTHA can be started with
```bash
VOLTHA_BUILD=docker make start
```

Eventually all the VOLTHA service will be started. You can view the service
list using
```bash
docker service ls
```

which should generate an output similar to

```bash
ID                  NAME                          MODE                REPLICAS            IMAGE                              PORTS
db4sd6qr4ovd        voltha_cli                    replicated          1/1                 voltha-cli:latest                  *:5022->22/tcp
f4am7jkrfkid        voltha_consul                 global              1/1                 consul:0.9.2                       *:8300->8300/tcp,*:8400->8400/tcp,*:8500->8500/tcp,*:8600->8600/udp
b0y0op65zijd        voltha_fluentd                replicated          1/1                 voltha-fluentd:latest              *:30011->24224/tcp
qqqba5wdug8i        voltha_fluentdactv            replicated          1/1                 voltha-fluentd:latest              *:30010->24224/tcp
aaba0xdriixw        voltha_fluentdstby            replicated          1/1                 voltha-fluentd:latest              *:30009->24224/tcp
watbhno8ylf6        voltha_freeradius             replicated          0/0                 marcelmaatkamp/freeradius:latest   *:1812->1812/udp,*:1813->1813/tcp,*:18120->18120/tcp
q58ptpueojha        voltha_kafka                  global              1/1                 wurstmeister/kafka:latest          *:9092->9092/tcp
pqp9o1z0ojpz        voltha_netconf                global              1/1                 voltha-netconf:latest              *:830->1830/tcp
sthhtxdv6trv        voltha_ofagent                replicated          1/1                 voltha-ofagent:latest
uk8c7f3cutpn        voltha_onos                   replicated          1/1                 voltha-onos:latest                 *:6653->6653/tcp,*:8101->8101/tcp,*:8181->8181/tcp
jauyicnmzy2m        voltha_onos_cluster_manager   replicated          1/1                 voltha-unum:latest                 *:5411->5411/tcp
vnsladm0ar0b        voltha_tools                  replicated          1/1                 voltha-tools:latest                *:4022->22/tcp
on4hpyuwiyw2        voltha_vcore                  replicated          1/1                 voltha-voltha:latest               *:8880->8880/tcp,*:18880->18880/tcp,*:50556->50556/tcp
u9g9vaip2nhf        voltha_voltha                 replicated          1/1                 voltha-envoy:latest                *:8001->8001/tcp,*:8443->8443/tcp,*:8882->8882/tcp,*:50555->50555/tcp
hyuak4pr8pt3        voltha_zk1                    replicated          1/1                 wurstmeister/zookeeper:latest
hdshxxj1sxoj        voltha_zk2                    replicated          1/1                 wurstmeister/zookeeper:latest
y70234pasn6g        voltha_zk3                    replicated          1/1                 wurstmeister/zookeeper:latest
```

After all the services are started you can access the VOLTHA CLI using `ssh`
```bash
ssh -p 5022 voltha@localhost
```

_NOTE: The default password used when `ssh`-ing into the VOLTHA CLI is
`admin`._


VOLTHA can be stopped with
```bash
VOLTHA_BUILD=docker make stop
```

### Running VOLTHA from pre-build docker images
The VOLTHA docker images are published on `dockerhub.com` as the `voltha`
repository: `https://hub.docker.com/u/voltha/`.

To run VOLTHA using this containers (and therefore not requiring a build) the
following command can be used

```bash
REPOSITORY=voltha/ VOLTHA_BUILD=docker make start
```

_NOTE: the slash (`/`) at the end of the `REPOSITORY` specification is
required._

Running VOLTHA in this way should produce the following `docker service ls`
output

```bash
ID                  NAME                          MODE                REPLICAS            IMAGE                              PORTS
86iemjy8q1e1        voltha_cli                    replicated          1/1                 voltha/voltha-cli:latest           *:5022->22/tcp
sm0zuqcq41go        voltha_consul                 global              1/1                 consul:0.9.2                       *:8300->8300/tcp,*:8400->8400/tcp,*:8500->8500/tcp,*:8600->8600/udp
vx5ir7dsciq3        voltha_fluentd                replicated          1/1                 voltha/voltha-fluentd:latest       *:30014->24224/tcp
x1ptzxq37cjw        voltha_fluentdactv            replicated          1/1                 voltha/voltha-fluentd:latest       *:30012->24224/tcp
wfu6ebh3id6a        voltha_fluentdstby            replicated          1/1                 voltha/voltha-fluentd:latest       *:30013->24224/tcp
h4r0z661t2u9        voltha_freeradius             replicated          0/0                 marcelmaatkamp/freeradius:latest   *:1812->1812/udp,*:1813->1813/tcp,*:18120->18120/tcp
hzhqj0rvjsh8        voltha_kafka                  global              1/1                 wurstmeister/kafka:latest          *:9092->9092/tcp
vzewlgoxb3j6        voltha_netconf                global              1/1                 voltha/voltha-netconf:latest       *:830->1830/tcp
v1uj00lyzgj8        voltha_ofagent                replicated          1/1                 voltha/voltha-ofagent:latest
bafqv7fvb1qb        voltha_onos                   replicated          1/1                 voltha/voltha-onos:latest          *:6653->6653/tcp,*:8101->8101/tcp,*:8181->8181/tcp
umams0s8jq6h        voltha_onos_cluster_manager   replicated          1/1                 voltha/voltha-unum:latest          *:5411->5411/tcp
tnn5ce8x4k89        voltha_tools                  replicated          1/1                 voltha/voltha-tools:latest         *:4022->22/tcp
h4c94dvhx0ig        voltha_vcore                  replicated          1/1                 voltha/voltha-voltha:latest        *:8880->8880/tcp,*:18880->18880/tcp,*:50556->50556/tcp
9l5ubtie7lt4        voltha_voltha                 replicated          1/1                 voltha/voltha-envoy:latest         *:8001->8001/tcp,*:8443->8443/tcp,*:8882->8882/tcp,*:50555->50555/tcp
k43f3a1wa0hv        voltha_zk1                    replicated          1/1                 wurstmeister/zookeeper:latest
kl5lpi0mt35e        voltha_zk2                    replicated          1/1                 wurstmeister/zookeeper:latest
t9eh5whkivfe        voltha_zk3                    replicated          1/1                 wurstmeister/zookeeper:latest
```

_Notice the image names in this output are prefixed with `voltha/`_

# Build VOLTHA CLI to use SSH Keys

The default CLI container build as part of VOLTHA only provides password
authentication. The following describes how you can build and use a custom
CLI container that uses custom SSH keys.

## Create the SSH Keys
The following command can be used to create a valid SSH key:
```bash
ssh-keygen -t rsa -N '' -f ./voltha_rsa
```

This should generate two files: `voltha_rsa` and `voltha_rsa.pub`.

_NOTE: If a different file name is for the key files then the environment
variable `PUB_KEY_FILE` will have to be specified when the
`make custom_cli` is executed, as described below. Additionally, when
`ssh`-ing to VOLTHA, the modified file should be used._

## Build the Custom CLI Container
There is a make target provided to build the custom CLI container. 
```bash
VOLTHA_BUILD=docker make custom_cli
```

The custom CLI container will, by default, be names `voltha-cli-custom`. If
you would like to customize the name of the custom docker CLI, this can be 
done by setting the environment varible `CUSTOM_CLI_LABEL` when executing
the `make` command, as shown as an example below.
```bash
CUSTOM_CLI_LABEL=-my-custom-cli VOLTHA_BUILD=docker make custom_cli
```

_NOTE: This make target will work with both the Docker and non-Docker builds._

## Running VOLTHA with the Custom CLI Container
Because the default `start` make target for VOLTHA uses the default CLI
container, the `CUSTOM_CLI_LABEL` must be specified when executing the
`start` make taget in order to use the custom CLI container.

```bash
CUSTOM_CLI_LABEL=-custom VOLTHA_BUILD=docker make start
```

## SSH-ing to VOLTHA
Now that the CLI is active with SSH keys, the following command can be
used to SSH without a password to VOLTHA

```bash
ssh -i voltha_rsa -p 5022 voltha@localhost
```
