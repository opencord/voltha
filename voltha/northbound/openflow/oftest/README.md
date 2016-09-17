## oftest test-cases to test the pyofagent

The main purpose of these tests is to verify correct packet-in and packet-out behavior of
pyofagent. Pyofagent can send and receive raw packets at a local interface. The interface
can be configured with the --in-out-iface=<link name> command line option. We will refer
to this interface below as the "in-out" interface.

Incoming frames arriving at the in-out interface are assumed to be single-tagged with a VLAN
id that represents a logical port number. Pyofagent will forward such frames to the controller
as OpenFlow "packet-in" messages, accompanied with the extracted port number is in_port
metadata.

Conversely, when pyofagent receives an OpenFlow "packet-out" message from the controller, it
will encapsualte the frame in an VLAN header with a VLAN id representing the out_port. If the
out_port is a list, pyofagent will replicate the frame and send it out once at each specified
port (that is, one with each of the specified VLAN ids).

### Setup required for the test:

You must have oftest checked out in a directory at the same level as the pyofagent root directory.
For instance, if pyofagent is under ~/olt, then oftest must be checked out also under ~/olt:

```
cd ~/olt
git clone git@bitbucket.org:corddesign/pyofagent.git
```

In order to run these test, we need to create a veth port pair on the host:

```
sudo ip link add ep1 type veth peer name ep2
sudo ifconfig ep1 up
sudo ifconfig ep2 up
```

To start pyofagent in the in-out mode, start it with the --in-out-iface option, such as:

```
cd ~/olt
sudo python pyofagent/pyofagent/main.py -v --in-out-iface=ep2
```

Now we can run the tests:

```
cd ~/olt
sudo ./oftest/oft --test-dir=pyofagent/oftest/ -i 1@ep1 --port 6633 -V 1.3 \
        --debug=verbose -t "in_out_port=1"
```

There are currently two tests, they should both pass. This proves that the packet in/out behavior of pyofagent is healthy.

