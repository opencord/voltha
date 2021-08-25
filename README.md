# DEPRECATED

[![No Maintenance Intended](http://unmaintained.tech/badge.svg)](http://unmaintained.tech/)

`VOLTHA 1.7` was the last release that officially supported the `voltha` core written in python as the core container for VOLTHA.
From `2.0` onwards the voltha core has been rewritten in go [voltha-go](https://github.com/opencord/voltha-go). This codebase is going to be removed after the VOLTHA 2.8 release LTS support ends in December 2022.

# VOLTHA

## What is Voltha?

Voltha aims to provide a layer of abstraction on top of legacy and next generation access network equipment for the purpose of control and management. Its initial focus is on PON (GPON, EPON, NG PON 2), but it aims to go beyond to eventually cover other access technologies (xDSL, Docsis, G.FAST, dedicated Ethernet, fixed wireless).

Key concepts of Voltha:

* **Network as a Switch**: It makes a set of connected access network devices to look like a(n abstract) programmable flow device, a L2/L3/L4 switch. Examples:
    * PON as a Switch
    * PON + access backhaul as a Switch
    * xDSL service as a Switch
* **Evolution to virtualization**: it can work with a variety of (access) network technologies and devices, including legacy, fully virtualized (in the sense of separation of hardware and software), and in between. Voltha can run on a decice, on general purpose servers in the central office, or in data centers.
* **Unified OAM abstraction**: it provides unified, vendor- and technology agnostic handling of device management tasks, such as service lifecycle, device lifecycle (including discovery, upgrade), system monitoring, alarms, troubleshooting, security, etc.
* **Cloud/DevOps bridge to modernization**: it does all above while also treating the abstracted network functions as software services manageable much like other software components in the cloud, i.e., containers.

## Why Voltha?

Control and management in the access network space is a mess. Each access technology brings its own bag of protocols, and on top of that vendors have their own interpretation/extension of the same standards. Compounding the problem is that these vendor- and technology specific differences ooze way up into the centralized OSS systems of the service provider, creating a lot of inefficiencies.

Ideally, all vendor equipment for the same access technology should provide an identical interface for control and management. Moreover, there shall be much higher synergies across technologies. While we wait for vendors to unite, Voltha provides an increment to that direction, by confining the differences to the locality of access and hiding them from the upper layers of the OSS stack.


## How can you work with Voltha?

While we are still at the early phase of development, you can check out the [BUILD.md](BUILD.md) file to see how you can build it, run it, test it, etc.

## How can you help?

Contributions, small and large, are welcome. Minor contributions and bug fixes are always welcome in form of pull requests. For larger work, the best is to check in with the existing developers to see where help is most needed and to make sure your solution is compatible with the general philosophy of Voltha.

### Contributing Unit Tests

To begin, make sure to have a development environement installed according to the [OpenCord WIKI](https://wiki.opencord.org/display/CORD/Installing+required+tools). 
Next, In a shell environment
```bash
source env.sh;             # Source the environment Settings and create a virtual environment
make utest-with-coverage;  # Execute the Unit Test with coverage reporting
```

### Unit-testing the Core
New unit tests for the core can be written in the [nosetest](https://nose.readthedocs.io/en/latest/) framework and can be found under <repo>/tests/utest/

### Unit-testing an Adapter
Each adapter's unit tests are discovered by the presence of a test.mk [submake file](https://www.gnu.org/software/make/manual/html_node/Include.html) underneath the adapter's directory. 
for example)

```Makefile
# voltha/adapters/my_new_adapter/test.mk

.PHONY test
test:
   @echo "Testing my amazing new adapter"
   @./my_test_harness
   
```

Voltha's test framework will execute the FIRST Target in the submake file as the unit test function.  It may include as many dependencies as needed, such as using a different python framework for testing (pytest, unittest, tox) or even alternate languages (go, rust, php).

In order for you adapter's test-coverage to be reported, make sure that your test_harness creates a coverage report in a [junit xml](https://www.ibm.com/support/knowledgecenter/en/SSUFAU_1.0.0/com.ibm.rsar.analysis.codereview.cobol.doc/topics/cac_useresults_junit.html) format.  Most test harnesses can easily produce this report format.  The [Jenkins Job](https://jenkins.opencord.org/job/voltha_unit-test/cobertura) will pick up your coverage report file if named appropriately **junit-report.xml** according to the Jenkins configuration. 
