Netopeer NETCONF Server
-----------------------

### Introduction

The __netopeer__ container package provides the netopeer netconf service along with a framework to 
ensure proper interaction with the Voltha service.

__NOTE__ 

    The netopeer package offers a framework to enable interaction with Voltha through 
    NETCONF RPC calls.  Only a few calls have been implemented to demonstrate how it can be done.
    Therefore, it is not a fully functional service and it is up to the community to enhance it by
    adding support for standard models (e.g. BBF).
  
### Package Content

The package contains the necessary components to successfully build and deploy
the netopeer container.  

__voltha-grpc-client__: 

    GRPC client golang library to interact with the Voltha GRPC service. 
    
    It is compiled as a shared library to serve as a layer between a NETCONF TransAPI C library 
    and the Voltha architecture. 

    TransAPI library -- Voltha GRPC client -- Voltha 
    
__voltha-netconf-model__

    Sample golang library used to translate between a C data structure to the format
    defined by a given YANG model.  This sample uses the VOLTHA YANG model as a reference.
    
    This package was implemented to facilitate the serialization from C to XML and thus,
    is totally optional.

__voltha-transapi__

    Sample transAPI library to add support for the Voltha YANG model to the Netopeer netconf server.
    This library can be used as a template to add support for other YANG models.
    
    The following command was used to build the initial skeleton of the model.
    
    ```
    lnctool --model voltha.yang transapi
    ```
    
    The package was also modified to simplify the installation process of dependent 
    libraries such as voltha-grpc-client.


### Build

If you wish to build this package, execute the following command.

```
make netopeer
```

Please note that the netopeer container does not currently get built by default.


### Dependencies

The netopeer container expects a running Voltha environment.


### Deploy

A docker-compose configuration is available to start the instance.

```
docker-compose -f compose/docker-compose-netopeer.yml -p nc up -d
```


### Using the built-in Netconf client

This installation also comes with the netopeer-cli.

To use it, you will first need to change the root passwd to allow you to login to the netconf-server

* Access the console of the netopeer docker instance

    ```docker exec -ti <instance name> bash```
    
* Change the root passwd

    ```
    [root@76531624ce88 /]# passwd
    Changing password for user root.
    New password: <enter your new password>
    Retype new password: <enter your new password again>
    passwd: all authentication tokens updated successfully.
    [root@76531624ce88 /]# 
    ```
    
* Start the netopeer-cli 

    ```
    [root@76531624ce88 /]# netopeer-cli
    netconf>
    ```

* Connect to the local netconf-server instance
    
    ```
    netconf> connect localhost
    root@localhost password: <password that you configured above>
    ```

* Issue a sample RPC command

    ```
    netconf> user-rpc
    ```
    
* Enter the following request:
    ```
    <voltha:VolthaGlobalService-GetVoltha xmlns:voltha="urn:opencord:params:xml:ns:voltha:voltha"/>
    ```
    
* Sample output

    ```
    netconf> user-rpc

    Result:
    <voltha>
        <version>0.9.0</version>
        <log_level>INFO</log_level>
        <instances/>
        <adapters/>
        <logical_devices/>
        <devices/>
        <device_groups/>
    </voltha>
    ```