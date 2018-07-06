# T3 - Verify EAPOL Remote Gateway Authentication

## Test Objective

* Purpose of this test is to verify that 802.1X EAPOL messages are forwarded to the ONOS from VOLTHA
    * Correct Tibit OLT and ONU PON environment
    * Logical device visible in VOLTHA CLI

## Test Configuration

* VOLTHA ensemble running as per [deployment instructions](V01_voltha_bringup_deploy.md).
* Start the freeradius container

```shell
docker-compose -f compose/docker-compose-auth-test.yml up -d freeradius
```

* Tibit OLT and ONUs registered as ACTIVE in VOLTHA

## Test Procedure

Now that this OLT is ACTIVE in VOLTHA, it should forward EAPOL
traffic. We can verify this by starting the RG emulator and observing
that EAPOL authentication does not succeed. To do this start our RG
docker container.

```shell
docker run --net=host --privileged --name RG -it voltha/tester bash
```

this should land you in a command prompt that looks like

```shell
root@8358ef5cad0e:/#
```

and at this prompt issue the following command

```shell
/sbin/wpa_supplicant -Dwired -iens9f1 -c /etc/wpa_supplicant/wpa_supplicant.conf
```

This should pass with the following output

```shell
Successfully initialized wpa_supplicant
ens9f1: Associated with 01:80:c2:00:00:03
WMM AC: Missing IEs
ens9f1: CTRL-EVENT-EAP-STARTED EAP authentication started
ens9f1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=4
ens9f1: CTRL-EVENT-EAP-METHOD EAP vendor 0 method 4 (MD5) selected
ens9f1: CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully
```

Note: The wpa_supplicant application will not terminate on its own.  After the EAP authentication has completed, it is appropriate to terminate the wpa_supplicant application.

```shell
Ctrl-C
```

## Pass/Fail Criteria

* EAPOL Authentication should pass
