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
docker-compose -f compose/docker-compose-system-test.yml up -d
nosetests -s tests/itests/voltha/test_cold_activation_sequence.py
```
* **Device_state_changes**: This tests uses the ponsim OLT and ONUs to exercise 
the device state changes (preprovisioning, enabled, disabled, reboot). 
It exercises the following areas:
    * Chameleon REST interface 
    * Voltha GRPC interface
    * Voltha data model and business logic
    * Ponsim_olt and Ponsim_onu adapters
    * Ponsim 

First start the Voltha ensemble:
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

* **Voltha_rest_apis**: This test exercises the Chameleon REST interface and 
indirectly
 the Voltha GPRC interface as well.  It tests both the Local and the Global 
 interfaces.
 
```
cd /cord/incubator/voltha
. ./env.sh
docker-compose -f compose/docker-compose-system-test.yml up -d
nosetests -s tests/itests/voltha/test_voltha_rest_apis.py
```    

* **Voltha_alarm_events**: This test exercises the creation and clearing of alarm events

The test will first verify that the kafka alarm topic exists.  It will then create a simulated_olt
device and verify that alarms are generated by the device.

First start the Voltha ensemble:
```
cd /cord/incubator/voltha
. ./env.sh
docker-compose -f compose/docker-compose-system-test.yml up -d
```    
Then start PONSIM in a separate window:
``` 
sudo -s
. ./env.sh
./ponsim/main.py -v -o 4 -a -f 5
``` 
Enable port forwarding
``` 
sudo -s
echo 8 > /sys/class/net/ponmgmt/bridge/group_fwd_mask            
``` 
Run the test:
``` 
cd /cord/incubator/voltha
. ./env.sh
nosetests -s tests/itests/voltha/test_voltha_alarm_events.py
```  

* **Voltha_alarm_filters**: This test exercises the alarm event filtering mechanism

The test will first verify that the kafka alarm topic exists.  It will then create two devices
along with a filter against one of the devices.  The test will validate that alarms are received
for the unfiltered device and alarms will be suppressed for the filtered device.

First start the Voltha ensemble:
```
cd /cord/incubator/voltha
. ./env.sh
docker-compose -f compose/docker-compose-system-test.yml up -d
```    
Then start PONSIM in a separate window:
``` 
sudo -s
. ./env.sh
./ponsim/main.py -v -o 4 -a -f 5
``` 
Enable port forwarding
``` 
sudo -s
echo 8 > /sys/class/net/ponmgmt/bridge/group_fwd_mask            
``` 
Run the test:
``` 
cd /cord/incubator/voltha
. ./env.sh
nosetests -s tests/itests/voltha/test_voltha_alarm_filters.py
```  

* **Dispatcher**:  This test exercises the requests forwarding via the Global 
handler.

During this test, the user will be prompted to start ponsim.  Use 
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

Run the test:
```
cd /cord/incubator/voltha
. ./env.sh
nosetests -s tests/itests/voltha/test_dispatcher.py
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
  
