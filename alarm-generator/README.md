## Automatic Alarm Generator

Alarm-generator is a process that sends a stream of simulate_alarm requests to Voltha. The rate at which the alarms are generated and the duration between alarm RAISE and alarm CLEAR can be configured using command line options. 

### Requirements

Voltha must be installed. A useful environment with the appropriate libraries already installed is the Voltha vcli container. This container can typically be entered using kubectl (for example, `kubectl -n voltha exec -it <vcli-container-name> bash`.

TODO: Eventually alarm-generator may be installed into its own container, deployable with helm. 

### Usage

The following command-line arguments are supported:

* **-C CONSUL, --consul CONSUL**. Specifies the hostname and port of the consul agent. *(default: localhost:8500)*
* **-L, --lookup**. Lookup Voltha endpoints based on service entries (see also the -C option)
* **-G, --global_requests**. All requests to the Voltha gRPC service are global.
* **-g GRPC_ENDPOINT, --grpc-endpoint GRPC_ENDPOINT**. \<hostname\>:\<port\> of Voltha gRPC service. *(default=localhost:50055)*
* **-d DEVICE_ID, --device_id DEVICE_ID**. Device id of the OLT device that simulated alarms will be sent for. If no device id is specified, then Voltha will be queried and the first available OLT device id will be used.
* **-o ONU_ID, --one_id ONU_ID**. Device id of the ONU to send in simulated alarms. If not specified, then Voltha will be queried, and all available ONUs attached to the OLT will be used.
* **-i INTF_ID, --intf_id INTF_ID**. Interface id to send in simulated alarms. If ONU_ID is unspecified (see -o option), then Voltha will be queried for the interface id, and this setting will be ignored.
* **-r RATE, --rate RATE**. Rate in alarms/second to generate. Fractional values are permitted. *(default: 0.1)*
* **-u DURATION, --duration DURATION**. Duration in seconds between alarm RAISE and alarm CLEAR. *(default: 1)*

### OLT and ONU information used in alarms 

Each simulated alarm typically has three arguments, an OLT device id, an ONU device id, and an interface id. These options may be configured from the command line (-d, -o, and -i), or they may be learned from Voltha if these three options are unspecified.

Specifying these options from the command line may be handy in those cases where an OLT is simulated rather than being physically present.

### Example usage

Generate 1 request per second, each request a duration of 2 seconds. Learn OLT and ONU information by querying Voltha:

    main.py -C consul:8500 -g voltha:50555 -G -r 1 -u 2

Generate 1 request per second, each request a duration of 2 seconds. For OLT id, use the first OLT found in Voltha. Use the onu_device_id 00012bc90d6552dd and the intf_id 0:

    main.py -C consul:8500 -g voltha:50555 -G -r 1 -u 2 -i 0 -o 00012bc90d6552dd

Generate 1 request every ten seconds, each request a duration of 4 seconds. OLT id,one_device_id, and intf_id are all configured from the command-line:

    main.py -C consul:8500 -g voltha:50555 -G -r 0.1 -u 4 -i 0 -o 00012bc90d6552dd -d 00012bc90d6552dd
