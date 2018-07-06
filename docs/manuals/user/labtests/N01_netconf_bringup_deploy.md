# N1 - Deploy Netconf and Verify its Vital Signs

## Test Objective

* Purpose of this test is to launch Netconf together with all of its dependencies and verify that all are in working condition.

## Test Configuration and Procedure

* Since Netconf is deployed as part of Voltha ensemble, follow the instructions from [Voltha](V01_voltha_bringup_deploy.md)

## Pass/Fail Criteria (Installation Checkpoint)

* The Pass/Fail criteria in [Voltha](V01_voltha_bringup_deploy.md) applies here as well. 
* Verify Netconf server is up and listening on port 1830.  Issue the following commands in the same Linux terminal:

```shell
docker-compose -f compose/docker-compose-system-test.yml logs netconf | grep 1830
```

Expected output are:

```shell
netconf_1 | <time> DEBUG    nc_server.start_ssh_server {port: 1830, event: starting, instance_id: compose_netconf_1}
netconf_1 | <time DEBUG    nc_server.start_ssh_server {port: 1830, event: started, instance_id: compose_netconf_1}
```
