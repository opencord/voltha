# S3 - Verify EAPOL Remote Gateway Authentication

## Test Objective

* Purpose of this test is to verify that 802.1X EAPOL messages are forwarded to the ONOS from VOLTHA
    * Correct simulated PON environment
    * Logical device visible in VOLTHA CLI

## Test Configuration

* VOLTHA ensemble running as per [deployment instructions](V01_voltha_bringup_deploy.md).
* Start the freeradius container

```shell
docker-compose -f compose/docker-compose-auth-test.yml up -d freeradius
```

* PONSIM OLT and ONUs registered as ACTIVE in VOLTHA

## Test Procedure

Execute the following command 

```shell
/sbin/wpa_supplicant -Dwired -ipon1_128 -c /etc/wpa_supplicant/wpa_supplicant.conf
```

This should pass with the following output

```shell
Successfully initialized wpa_supplicant
pon1_128: Associated with 01:80:c2:00:00:03
WMM AC: Missing IEs
pon1_128: CTRL-EVENT-EAP-STARTED EAP authentication started
pon1_128: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=4
pon1_128: CTRL-EVENT-EAP-METHOD EAP vendor 0 method 4 (MD5) selected
pon1_128: CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully
```

## Pass/Fail Criteria

* EAPOL Authentication should pass
