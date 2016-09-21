
To get this agent to work with the ONOS olt-test, the following
command was used in the shell to launch the agent.

NOTE: This command should soon be eliminated as the agent should
be started by VOLTHA.

```
$ cd <LOCATION_OF_VOLTHA>
$ sudo -s
# . ./env.sh
# cd <LOCATION_OF_VOLTHA>/voltha/northbound/openflow
(venv-linux) # python agent/main.py -v --in-out-iface=enp1s0f0 --in-out-stag=4004
```

