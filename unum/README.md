# E  Pluribus Unum

This micro-service provides an ONOS cluster manager capability to enable
dynamic cluster configuration within container orchestration environments.

This service uses information about the service to determine when all the
nodes of a cluster are *ready* and then serves an ONOS cluster configuration
via `HTTP`. Until all the ONOS instances are *ready* the service will return
a `204 No Content` response.

## Configuration
The `unum` container supports the following configuration options that are
set via environment variables on a container instance:

| KEY | DEFAULT | DESCRIPTION |
| --- | --- | --- |
|  ORCHESTRATOR | `swarm://` | specifies how to connect to the container orchestration system, currently only `swarm://` is supported |
| LABELS | `org.onosproject.cluster:true` | used to identify ONOS instances that should be part of the cluster, the label and value must match |
| NETWORK | `org.onosproject.cluster:true` | used to identify the network to which ONOS is connected that should be used when selecting an IP address to use for ONOS clustering, the label and value must match |
| LISTEN | `0.0.0.0:5411` | interface and port on which to listen for ONOS cluster meta data requests |
| PERIOD | `20s` | period at which to poll the container orchestration system for service information |
| LOG_LEVEL | `warn` | level at which to log messages to the console |
| LOG_FORMAT | `text` | format for log messages, `text` or `json` |

## Makefile Targets
```
Available make targets:
  image     - build the docker image
  deploy    - deploys a sample 3 instance cluster
  logs      - displays the logs of the unum container
  nodes     - ssh to ONOS and display state of nodes in cluster
  rm        - remove the sample 3 instance cluster
```

## Caveats
with release `1.10.4` of ONOS, if ONOS is configured with an external meta data
source and ONOS cannot connect to that meta data source (URL) upon start up or
if the source returns anything other than `204 No Content` or `200 OK` then
ONOS cluster will be in an error state and the meta data source will not be
queried further.

This can be an issue in a container orchestration or micro-service environments
where the startup sequence cannot and should not be guaranteed.

There is a patch to ONOS to resolve this issue, but it has not yet (5-SEP-2017)
been merged.

## Improvements
Currently the unum container works on a polling mechanism. It would be better
if instead it registered for events from the orchestration system to understand
when services and containers were created and reacted to those events as opposed
to poll. The issue is that currently the supported container orchestration
systems do not provide cluster-wide events. This area should be investigated
further to see if eventing can be leveraged in some way.
