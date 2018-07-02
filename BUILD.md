# How to Build and Develop Voltha

There are many ways to build and develop Voltha:

* Use the provided Vagrant environment. This mode is by far the most reliable, and the only one officially supported.
* Use your native MAC OS or Linux environments. These are not supported, although we provide guidance in a best effort manner and contributions/patches are graciously accepted from the community.

## Build and Develop on the Vagrant Box

### Prerequisites

* Repo client (see below)
* Working installation of Vagrant 1.9.1 or later -- see [https://www.vagrantup.com/downloads.html](https://www.vagrantup.com/downloads.html)
* jq -- a useful command line too to work with JSON data. On the MAC, you can install jq with ```brew install jq```; on Ubuntu you can do it with ```sudo apt-get install jq```. You will not regret it.

### Repo

To checkout the the voltha source code you will need to install repo. Intructions for this can be found [here](https://wiki.opencord.org/display/CORD/Setting+up+and+using+REPO)

### Build

If you have not cloned Voltha, it's time to do it now.

```
repo init -u https://gerrit.opencord.org/manifest -g voltha
repo sync
```

You can build Voltha by:

```
cd opencord/incubator/voltha
vagrant up  # when you do this for the first time, this will take considerable time
vagrant ssh # the rest to be executed inside the vagrant VM
cd /cord/incubator/voltha
. env.sh
make fetch
make build
```

The above has generated a new Docker image '''voltha/voltha''' inside the VM. To see it, run:

```
docker images
```

### Run in stand-alone mode

The simplest way to run the image (in the foreground):

```
docker run -ti --rm voltha/voltha
```

Unless you happen to have a consul agent running on your local system, you shall see that voltha is trying to connect to a consul agent, without success.

To bring up a consul agent, you can use docker-compose with the provided compose file:

```
docker-compose -f compose/docker-compose-system-test.yml up -d consul
```

You may get a warning from docker-compose about an empty environment variable, which you can ignore for now.

By now you should have consul running, which you can verify:

```
docker-compose -f compose/docker-compose-system-test.yml ps
```

To verify that consul is indeed up, you can point your web browser to [http://localhost:8500/ui](http://localhost:8500/ui).
Alternatively, you can use curl to access consul's REST API. For example:

```
curl -s http://localhost:8500/v1/status/leader | jq -r .
```

This should print the IP address (on the docker network) and port number of the internal gossip API for our consul instance (you can ignore the actual data).

Once consul is up, you can extract its IP address programmatically by:

```
CONSUL_IP=`docker inspect compose_consul_1 | \
    jq -r '.[0].NetworkSettings.Networks.compose_default.IPAddress'`
```

With the IP address in hand, you can now start Voltha manually as:

```
docker run -ti --rm --net=compose_default voltha/voltha /voltha/voltha/main.py --consul=$CONSUL_IP:8500
```

This time it should successfully connect to consul and actually register itself.
You should see a log line simialr to the following:

```
<timestamp> INFO     coordinator._create_session {session_id: <session_id, event: created-consul-session, instance_id: <instance_id}
```

To test Voltha's self-registration with consul, run this (in another terminal):

```
curl -s http://localhost:8500/v1/kv/service/voltha/members?recurse | jq -r .
```

This should print one key-value entry, something similar to:

```
[
  {
    "ModifyIndex": 19,
    "CreateIndex": 19,
    "Session": "139181ff-d4f8-d11c-c450-c41de4baa7d7",
    "Value": "YWxpdmU=",
    "Flags": 0,
    "Key": "service/voltha/members/23d0f3db5877",
    "LockIndex": 1
  }
]
```

The above is an ephemeral record in consul. To see how it is auto-deleted, stop the voltha container (with Ctrl-C) and rerun the above curl query again. This time you should no output form the query.

To clean up, stop consul:

```
docker-compose -f compose/docker-compose-system-test.yml stop
docker-compose -f compose/docker-compose-system-test.yml rm -f
```

### Run with the "voltha ensamble"

Voltha's intended use is with a consul+fluent+registrator combo. You can bring up this entire ensamble in a developer mode, with just one command. But first, you need to setup your local environment variable. This needs to be done only once in a terminal session:

```
source env.sh
```

To start the eight-container ensamble:

```
docker-compose -f compose/docker-compose-system-test.yml up -d
```

There are a lot of things going on between these containers:

1. To verify that they are all up and happy, you can use:

   ```
   docker-compose -f compose/docker-compose-system-test.yml ps
   ```
   
   Naturally, you can always use plain docker commands too:
   
   ```
   docker ps -a
   ```
   
2. The registrator container is auto-registering docker containers and their services with consul. This will be handy when accessing the voltha cluster from the north-bound. To see the auto-registrations via Consul's HTTP API:

   ```
   curl -s http://localhost:8500/v1/catalog/services | jq -r .
   ```
   
   This shall list something like this:
   
   ```
   {
      "zookeeper": [],
      "chameleon-rest": [],
      "consul": [],
      "consul-8600": [
        "udp"
      ],
      "consul-rest": [],
      "fluentd-intake": [],
      "kafka": [],
      "voltha-grpc": [],
      "voltha-health": []
   }
   ```
   
   You don't see registrator itself, and you see multiple entries for consul. More importantly you see voltha as a service called "voltha-health" (referring to the REST health check service of voltha). You can query additional info on this endpoint from consul:
   
   ```
   curl -s http://localhost:8500/v1/catalog/service/voltha-health | jq -r .
   ```
   
   This will provide the complete service record for the voltha instance:
   
   ```
   [
     {
       "ModifyIndex": 14,
       "CreateIndex": 9,
       "ServiceEnableTagOverride": false,
       "Node": "ff30117fb001",
       "Address": "172.18.0.3",
       "TaggedAddresses": {
         "wan": "172.18.0.3",
         "lan": "172.18.0.3"
       },
       "ServiceID": "ef1b466f2ede:compose_voltha_1:8880",
       "ServiceName": "voltha-health",
       "ServiceTags": [],
       "ServiceAddress": "10.0.2.15",
       "ServicePort": 32768
     }
   ]
   ```

3. Voltha is logging to its standard output, which is captured by docker. There are multiple ways to access this log stream:
  
   To see (and tail) logs form all running containers that are part of the voltha: 
  
   ```
   docker-compose -f compose/docker-compose-system-test.yml logs
   ```
  
   Once important thing you can see is that voltha uses structured logging, which will come handy once we utilize machine parsing and filtering of the logs.
  
   Alternatively, you can see the individual docker log stream of voltha by:
  
   ```
   docker logs -f compose_voltha_1
   ```
  
   Voltha sends a periodic log message (heartbeat) to the log stream, in addition to logging major events.  Voltha also sends a periodic heartbeat message to the kafka broker.
   
   To subscribe and display to the kafka messages:
   
   ```
   python kafka/kafka-consumer.py
   ```


4. In addition to the docker log stream, Voltha is explicitly hooked up to the fluentd log collector infrastructure. We are not using fluentd to its full potential yet, but establishing the connection to fluentd and funnelling structured logs to fluentd is already in place. To see the fluentd log stream, you can run:
  
   ```
   tail -F /tmp/fluentd/*.log
   ```
  
5. When regstrator registers voltha with consul, it also initiates a periodic healt-check from consul to the voltha instance. This is done by calling the ```http://<voltha-instance-ip>:<port>/health``` REST API of voltha. This does not yet do too much, but helps consul to flag a voltha instance "failing" should it not reply to the REST request in a timely manner.
  
   If you look into the lo stream of voltha, you can see an entry every 3 seconds indicating that voltha received the health check request and responded (you need -v (verbose mode) enabled to see these).
  
   One way to see the health checks are passing is to point your browser to the user interface of consul: [http://10.100.198.220:8500/ui](http://10.100.198.220:8500/ui). Click on the voltha-health entry and you shall see its passing two health tests, the one with the name volta-rest is our healthcheck.
  
6. Consul exposes the service records also as a DNS server. This is how it can be used:

   To check the IP address(es) for voltha's REST interface, you can use:
   
   ```
   dig @localhost -p 8600 voltha-health.service.consul
   ```
   
   Which shall print, among other things an A record:
   
   ```
   voltha-health.service.consul. 0  	IN     	A      	10.0.2.15
   ```
   
   Or if you want the IP adress only:
   
   ```
   dig @localhost -p 8600 +short voltha-health.service.consul
   ```
   
   Which shall print just an IP address.
   
   If you want the exposed service port as well:
   
   ```
   dig @localhost -p 8600 +short voltha-health.service.consul SRV
   ```
   
   The 3rd field in the response is the exposed TCP port voltha's REST API is accessible.
   
7. Now something really cool: voltha can be scaled out horizontally to multiple containers by:

   ```
   docker-compose -f compose/docker-compose-system-test.yml scale voltha=10
   ```
   
   This will bring up nine (9) additional voltha instances as new docker containers. After this completes we encourage you to re-run steps 5, 6 and 7, and observe the changes.
   
Finally, you can clean up:

To stop all docker instances started by docker-compose, just run:

```
docker-compose -f compose/docker-compose-system-test.yml stop
docker-compose -f compose/docker-compose-system-test.yml rm -f
```

Or, you can just wipe out your whole Vagrant instance:

```
exit # from vagrant box back to your native environmnet
vagrant destroy -f
```

### Single-node Kubernetes

To run voltha in a Kubernetes environment, the "voltha" development machine can be configured as a Kubernetes master running in a single-node cluster.

To install Kubernetes, execute the following ansible playbook:
```
cd /cord/incubator/voltha
ansible-playbook ansible/kubernetes.yml -c local
```
Wait for the kube-dns pod to reach the Running state by executing the command:
```
kubectl get pods --all-namespaces -w
```
Run this next command to create the "voltha" namespace"
```
kubectl apply -f k8s/namespace.yml
```
Follow the steps in either one of the next two sub-sections depending on whether a Consul or Etcd KV store is to be used with voltha.

#### Single-node Kubernetes with Consul KV store

In order to access the Consul UI, set up the ingress framework:
```
kubectl apply -f k8s/ingress/
```
Deploy the base components:
```
kubectl apply -f k8s/single-node/zookeeper.yml
kubectl apply -f k8s/single-node/kafka.yml
kubectl apply -f k8s/single-node/consul.yml
kubectl apply -f k8s/single-node/fluentd.yml
```
The following steps will succeed only if the voltha images have been built:
```
kubectl apply -f k8s/single-node/vcore_for_consul.yml
kubectl apply -f k8s/single-node/ofagent.yml
kubectl apply -f k8s/envoy_for_consul.yml   # Note the file path
kubectl apply -f k8s/single-node/vcli.yml
kubectl apply -f k8s/single-node/netconf.yml
```
To deploy the monitoring components (Note the file paths):
```
kubectl apply -f k8s/grafana.yml
kubectl apply -f k8s/stats.yml
```

#### Single-node Kubernetes with Etcd KV store

Deploy the base components:
```
kubectl apply -f k8s/single-node/zookeeper.yml
kubectl apply -f k8s/single-node/kafka.yml
kubectl apply -f k8s/operator/etcd/cluster_role.yml
kubectl apply -f k8s/operator/etcd/cluster_role_binding.yml
kubectl apply -f k8s/operator/etcd/operator.yml
kubectl apply -f k8s/single-node/etcd_cluster.yml
kubectl apply -f k8s/single-node/fluentd.yml
```
The following steps will succeed only if the voltha images have been built:
```
kubectl apply -f k8s/single-node/vcore_for_etcd.yml
kubectl apply -f k8s/single-node/ofagent.yml
kubectl apply -f k8s/envoy_for_etcd.yml
kubectl apply -f k8s/single-node/vcli.yml
kubectl apply -f k8s/single-node/netconf.yml
```
To deploy the monitoring components (Note the file paths):
```
kubectl apply -f k8s/grafana.yml
kubectl apply -f k8s/stats.yml
```

# Testing

   Follow the steps below to run integration testing. Note: All output 
    are directed to the shell:

   ```
   make itest
   ```

# Building natively on MAC OS X

For advanced developers this may provide a more comfortable developer
environment (e.g., by allowing IDE-assisted debugging), but setting it up
can be a bit more challenging.

### Prerequisites

* git installed
* Docker-for-Mac installed
* Python 2.7
* virtualenv
* brew (or macports if you prefer)
* protoc

### Installing Voltha dependencies

The steps that may work (see list of workarounds in case it does not):

```
git clone git@bitbucket.org:corddesign/voltha.git
cd voltha
make venv
```

Potential issues and workaround:

1. Missing virtualenv binary. Resolution: install virtualenv.

   ```
   brew install python pip virtualenv
   ```

1. 'make venv' exits with error 'openssl/opensslv.h': file not found.
   Resolution: install openssl-dev and add a CFLAGS to make venv:

   MAC OS:
   ```
   brew install openssl
   ```

   Linux:
   ```
   sudo apt-get install libssl-dev
   ```

   Note the version that it installed. For example, '1.0.2h_1'.
   Rerun ```make venv``` as:

   ```
   env CFLAGS="-I /usr/local/Cellar/openssl/1.0.2h_1/include" make venv
   ```
 
### Building Docker Images and Running Voltha

These steps are not different from the Vagrant path:

```
make build
```

Then you shall be able to see the created image and run the container:

```
docker run -ti voltha/voltha
```

After this, much or all of the things you can do inside the Vagrant box should also work natively on the Mac.


### Test Issues and Workarounds

 1. The dreaded "Need to install scapy for packet parsing" error when running
 olt-oftest based tests. This is due to a missing dnet package which scapy
 needs. Workaround:
 
    ```
    brew uninstall libdnet
    brew install --with-python libdnet
    cd $VOLTHA_BASE
    echo 'import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")' \
        >> venv-darwin/lib/python2.7/site-packages/homebrew.pth
    pip install pcapy
    pip install scapy
    pip install pypcap
    ```

 2. Missing mininet.topo module (used by oftest):
  
  Unfortunately I was not yet able to resolve this on the Mac.

### Scapy related import issues on MAC OS

 1. I had issues with "from scapy.all import *". It errored out with import error not finding
dumbnet. The following resolved the issue:

   ```
   cd $VOLTHA_BASE
   . env.sh
   mkdir tmp
   cd tmp
   git clone https://github.com/dugsong/libdnet.git
   cd libdnet
   ./configure
   make
   sudo make install
   cd python
   python setup.py install
   cd ../..
   rm -fr tmp
   ```

