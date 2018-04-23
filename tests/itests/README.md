## VOLTHA TESTS

There are two set of test cases in Voltha:
* **Unit Tests**
    *  These tests exercise the smallest testable parts of the code. They 
    are designed to be fully automated and can be executed by a build 
    machine (e.g. Jenkins).  
 * **Integration Tests**
    * These tests exercise a set of modules when combined together
    
For now, this document focuses on running the integration tests only.

##### Running the Integration Tests

This section provides the high level details on how to execute the Voltha 
integration tests when running inside a Vagrant box.   They may need to be 
adjusted when run in a different environment.

* **Build_md_test**: This tests the instructions in the voltha/BUILD.md file. 
Note that this test takes a while to run (more than 40 mins).  
```
cd /cord/incubator/voltha
. ./env.sh
nosetests -s tests/itests/docutests/build_md_test.py
```
* **Ofagent_multicontroller_failover**: This tests the OFAgent capability
to work seamlessly with multiple ONOS controllers. Note that no dockers
containers should be running(to avoid host side port usage conflicts).
Also note this test takes a while to run (close to 5 mins).
The steps it follows are
    * Spawns three ONOS controllers and clusters them.
    * Spawns required Voltha components.
    * OFagent establishes connection with the three spawned controllers.
    * Adds simulated OLT and enables it.
    * Identifies the ONOS controller having the Mastership role for the
      above added OLT and kills it.
    * Tests if new master is chosen among the remaining two ONOS controllers.

```
cd /cord/incubator/voltha
. ./env.sh
nosetests -s tests/itests/ofagent/test_ofagent_multicontroller_failover.py
```
* **Ofagent_recovery**: This tests the OFAgent capability
to recover the connectivity with Voltha after a component failure.
Also note this test takes a while to run (approximately 6 mins).
The steps it follows are
    * Spawns three ONOS controllers and clusters them.
    * Spawns required Voltha components.
    * OFagent establishes connection with the three spawned controllers.
    * Adds simulated OLT and enables it.
    * Stop/start OFAgent and VOLTHA processes (2 separate tests)
    * Ensure that the OLT created prior to stopping process is still present
    * Adds another simulated OLT to ensure connectivity

```
cd /cord/incubator/voltha
. ./env.sh
nosetests -s tests/itests/ofagent/test_ofagent_recovery.py
```
* **Frameio**:  This tests the packet send/receive/filter capabilities of the 
FrameIOManager.   This test needs to run as root.
```
cd /cord/incubator/voltha
. ./env.sh
make run-as-root-tests
```
* **Cold_activation_sequence**: This test creates the simulated_olt devices and 
run through a cold activation sequence.  It exercises the following 
areas:
    * Chameleon REST interface 
    * Voltha GRPC interface
    * Voltha data model and business logic    
    * Simulated Adapter
    
```
cd /cord/incubator/voltha
. ./env.sh
```
To run the test in the docker-compose environment:
```
docker-compose -f compose/docker-compose-system-test.yml up -d
nosetests -s tests/itests/voltha/test_cold_activation_sequence.py
```
To run the test in a single-node Docker swarm environment (see document voltha/DOCKER_BUILD.md):
```
VOLTHA_BUILD=docker make start
nosetests -s tests/itests/voltha/test_cold_activation_sequence.py --tc-file=tests/itests/env/swarm-consul.ini
```
To run the test in a single-node Kubernetes environment (see document voltha/BUILD.md):
```
./tests/itests/env/voltha-k8s-start.sh
nosetests -s tests/itests/voltha/test_cold_activation_sequence.py --tc-file=tests/itests/env/k8s-consul.ini
```
* **Device_state_changes**: This tests uses the ponsim OLT and ONUs to exercise 
the device state changes (preprovisioning, enabled, disabled, reboot). 
It exercises the following areas:
    * Envoy REST interface 
    * Voltha GRPC interface
    * Voltha data model and business logic
    * Ponsim_olt and Ponsim_onu adapters
    * Ponsim 

To run the test in the docker-compose environment, first start the Voltha ensemble:
```
cd /cord/incubator/voltha
. ./env.sh
docker-compose -f compose/docker-compose-system-test.yml up -d
```    
Then start PONSIM in a separate window:
``` 
sudo -s
. ./env.sh
./ponsim/main.py -v -o 4
```
Run the test:
``` 
cd /cord/incubator/voltha
. ./env.sh
nosetests -s tests/itests/voltha/test_device_state_changes.py
```  
To set up the test in a single-node Kubernetes environment (see document voltha/BUILD.md):
```
. ./env.sh
./tests/itests/env/voltha-k8s-start.sh
```
Refer to the Kubernetes section in document voltha/ponsim/v2/README.md to set up the node for PONSIM. To install the CNI plugin, you may enter:
```
kubectl apply -f k8s/genie-cni-1.8.yml
```
To run the test:
```
nosetests -s tests/itests/voltha/test_device_state_changes.py --tc-file=tests/itests/env/k8s-consul.ini
```

* **Persistence**: This test goes through several voltha restarts along with variations 
of configurations in between to ensure data integrity is preserved.
        
During this test, the user will be prompted to start ponsim.  Use 
these commands to run ponsim with 1 OLT and 4 ONUs. This will also 
enable alarm at a frequency of 5 seconds:
``` 
sudo -s
. ./env.sh
./ponsim/main.py -v -o 4 -a -f 5
``` 

The user will also be prompted to enable port forwarding on ponmgmt 
bridge. Use these commands:
``` 
sudo -s
echo 8 > /sys/class/net/ponmgmt/bridge/group_fwd_mask            
``` 

Run the test:
``` 
cd /cord/incubator/voltha
. ./env.sh
nosetests -s tests/itests/voltha/test_persistence.py
```

* **Voltha_rest_apis**: This test exercises the Envoy REST interface and 
indirectly
 the Voltha GPRC interface as well.  It tests both the Local and the Global 
 interfaces.
 
```
cd /cord/incubator/voltha
. ./env.sh
```
To run the test in the docker-compose environment:
```
docker-compose -f compose/docker-compose-system-test.yml up -d
nosetests -s tests/itests/voltha/test_voltha_rest_apis.py
```
To run the test in a single-node Docker swarm environment (see document voltha/DOCKER_BUILD.md):
```
VOLTHA_BUILD=docker make start
nosetests -s tests/itests/voltha/test_voltha_rest_apis.py --tc-file=tests/itests/env/swarm-consul.ini
```
To run the test in a single-node Kubernetes environment (see document voltha/BUILD.md):
```
./tests/itests/env/voltha-k8s-start.sh
nosetests -s tests/itests/voltha/test_voltha_rest_apis.py --tc-file=tests/itests/env/k8s-consul.ini
```
* **Voltha_alarm_events**: This test exercises the creation and clearing of alarm events

The test will first verify that the kafka alarm topic exists.  It will then create a simulated_olt
device and verify that alarms are generated by the device.

To run the test in the docker-compose environment,
start the Voltha ensemble and then execute the test:
```
cd /cord/incubator/voltha
. ./env.sh
docker-compose -f compose/docker-compose-system-test.yml down
docker-compose -f compose/docker-compose-system-test.yml up -d
nosetests -s tests/itests/voltha/test_voltha_alarm_events.py
```

To run the test in a single-node Kubernetes environment (see document voltha/BUILD.md),
start the Voltha ensemble:
```
./tests/itests/env/voltha-k8s-stop.sh
./tests/itests/env/voltha-k8s-start.sh
```
Wait until all the Voltha pods are in the Running state and take note of
Kafka's pod IP address. Enter the following line into the /etc/hosts file:
```
<kafka-pod-IP-address> kafka-0.kafka.voltha.svc.cluster.local
```
The test invokes the kafkacat client which complains that it can't resolve
kafka-0.kafka.voltha.svc.cluster.local. This domain name is only accessible
from within pods deployed to the Kubernetes cluster. The test, however, runs
outside the cluster. There may be another solution to this problem, but for
now, this may have to do. Once the test is fully automated, /etc/hosts can
be modified by the test itself.

To run the test:
```
nosetests -s tests/itests/voltha/test_voltha_alarm_events.py --tc-file=tests/itests/env/k8s-consul.ini
```

* **Voltha_alarm_filters**: This test exercises the alarm event filtering mechanism

The test will first verify that the kafka alarm topic exists.  It will then create two devices
along with a filter against one of the devices.  The test will validate that alarms are received
for the unfiltered device and alarms will be suppressed for the filtered device.

To run the test in the docker-compose environment,
start the Voltha ensemble and then execute the test:
```
cd /cord/incubator/voltha
. ./env.sh
docker-compose -f compose/docker-compose-system-test.yml down
docker-compose -f compose/docker-compose-system-test.yml up -d
nosetests -s tests/itests/voltha/test_voltha_alarm_filters.py
```
To run the test in a single-node Kubernetes environment (see document voltha/BUILD.md),
start the Voltha ensemble:
```
./tests/itests/env/voltha-k8s-stop.sh
./tests/itests/env/voltha-k8s-start.sh
```
Wait until all the Voltha pods are in the Running state and take note of
Kafka's pod IP address (See description for Voltha_alarm_events test).
Enter the following line into the /etc/hosts file:
```
<kafka-pod-IP-address> kafka-0.kafka.voltha.svc.cluster.local
```
To run the test:
```
nosetests -s tests/itests/voltha/test_voltha_alarm_filters.py --tc-file=tests/itests/env/k8s-consul.ini
```

* **Dispatcher**:  This test exercises the requests forwarding via the Global 
handler.

To run the test in the docker-compose environment:
```
cd /cord/incubator/voltha
. ./env.sh
nosetests -s tests/itests/voltha/test_dispatcher.py
```  

During the test, the user will be prompted to start ponsim.  Use 
these commands to run ponsim with 1 OLT and 4 ONUs.

``` 
sudo -s
. ./env.sh
./ponsim/main.py -v -o 4 
``` 

The user will also be prompted to enable port forwarding on ponmgmt 
bridge. Use these commands:

``` 
sudo -s
echo 8 > /sys/class/net/ponmgmt/bridge/group_fwd_mask            
``` 

To run the test in Kubernetes, set up a single-node environment by following
document voltha/BUILD.md. The test is fully automated; simply execute:
```
nosetests -s tests/itests/voltha/test_dispatcher.py --tc-file=tests/itests/env/k8s-consul.ini
```
* **Voltha_Xpon**: This test uses the ponsim-OLT to verfiy addition, modification and deletion 
of channelgroups, channelpartition, channelpair, channeltermination, VOntani, Ontani, VEnet for xpon

First start the Voltha ensemble:
```
cd /cord/incubator/voltha
. ./env.sh
docker-compose -f compose/docker-compose-system-test.yml up -d
```    
Then start PONSIM in a separate window:
``` 
sudo -s
cd /cord/incubator/voltha
. ./env.sh
./ponsim/main.py -v
```
Now Run the test in the first window:
``` 
nosetests -s tests/itests/voltha/test_voltha_xpon.py
```
  
