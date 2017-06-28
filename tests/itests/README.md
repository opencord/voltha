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
* **Ofagent_multicontroller_failover**: TODO   

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
nosetests -s tests/itests/voltha/test_device_state_changes.py
```  

* **Persistence**: This test goes through several voltha restarts along with variations 
of configurations in between to ensure data integrity is preserved.
        
During this test, the user will be prompted to start ponsim.  Use 
these commands to run ponsim with 1 OLT and 4 ONUs. THis will also 
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

* Voltha_alarm_events: TODO

* Voltha_alarm_filters: TODO
