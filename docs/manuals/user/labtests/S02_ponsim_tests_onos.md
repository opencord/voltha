# S2 - Attach the PONSIM OLT to ONOS

## Test Objective

Observe that ONOS has identified the OLT device and displays the correct number of ONU ports

## Test Configuration

* VOLTHA ensemble up and running.
* PONSIM configured with an OLT with multiple ONUs

## Test Procedure

First, start the onos container.

```shell
docker-compose -f compose/docker-compose-auth-test.yml up -d onos
```

this should output

```shell
Creating compose_onos_1
```

Make sure that ONOS is running

```shell
docker-compose -f compose/docker-compose-auth-test.yml ps
```

which shows

```shell
Name             Command         State                                        Ports
------------------------------------------------------------------------------------------------------------------------------
compose_onos_1   ./bin/onos-service   Up      0.0.0.0:6653->6653/tcp, 0.0.0.0:8101->8101/tcp, 0.0.0.0:8181->8181/tcp, 9876/tcp
```

Now, let's login to ONOS.

```shell
sudo apt install sshpass # may not be necessary
sshpass -p karaf ssh -o StrictHostKeyChecking=no -p 8101 karaf@localhost
```

this should land you at the ONOS prompt

```shell
Welcome to Open Network Operating System (ONOS)!
     ____  _  ______  ____
    / __ \/ |/ / __ \/ __/
   / /_/ /    / /_/ /\ \
   \____/_/|_/\____/___/

Documentation: wiki.onosproject.org
Tutorials:     tutorials.onosproject.org
Mailing lists: lists.onosproject.org

Come help out! Find out how at: contribute.onosproject.org

Hit '<tab>' for a list of available commands
and '[cmd] --help' for help on a specific command.
Hit '<ctrl-d>' or type 'system:shutdown' or 'logout' to shutdown ONOS.

onos>
```

Let's have a look at the devices that ONOS sees, to do this enter the following at the ONOS prompt.

```shell
devices
```

this will output the following

```shell
id=of:0000000000000001, available=true, role=MASTER, type=SWITCH, mfr=cord porject, hw=simualted pon, sw=simualted pon, serial=46da01fd646d4bb08140fc09b1bc4926, driver=voltha, channelId=172.25.0.1:35866, managementAddress=172.25.0.1, name=of:0000000000000001, protocol=OF_13
```

next let's have a look at the ports that onos sees. Remember that ONOS sees the PON system as a logical device so ONU are represented as ports to ONOS. So let's see the ports in ONOS.

```shell
ports
```

which returns the following

```shell
id=of:0000000000000001, available=true, role=MASTER, type=SWITCH, mfr=cord porject, hw=simualted pon, sw=simualted pon, serial=46da01fd646d4bb08140fc09b1bc4926, driver=voltha, channelId=172.25.0.1:35866, managementAddress=172.25.0.1, name=of:0000000000000001, protocol=OF_13
  port=0, state=enabled, type=fiber, speed=0 , portName=nni, portMac=00:00:00:00:00:00
  port=128, state=enabled, type=fiber, speed=0 , portName=uni-128, portMac=00:00:00:00:00:80
  port=129, state=enabled, type=fiber, speed=0 , portName=uni-129, portMac=00:00:00:00:00:81
  port=130, state=enabled, type=fiber, speed=0 , portName=uni-130, portMac=00:00:00:00:00:82
```

This correctly shows three ports. Yay!

## Pass/Fail Criteria

* OLT observed in ONOS
* ONUs observed in ONOS as ports
