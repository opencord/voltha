## VOLTHA TESTS

There are two set of test cases in Voltha:
* **Unit Tests**
    *  These tests exercise the smallest testable parts of the code. They 
    are designed to be fully automated and can be executed by a build 
    machine (e.g. Jenkins).  
 * **Integration Tests**
    * These tests exercise a set of modules when combined together
    
This document focuses on running the unit tests only.

##### Running the utests
* **Triggering all the utests as a batch run**: Unit tests under voltha can be run as follows:
```
cd /cord/incubator/voltha/
. ./env.sh
make utest
```
* **OFAgent utests**: A set of unit tests that are executed against the VOLTHA-OFAgent Code base.
Note that this test needs to run being inside ofagent directory. 
```
cd /cord/incubator/voltha/
. ./env.sh
nosetests -s tests/utests/ofagent/
```
