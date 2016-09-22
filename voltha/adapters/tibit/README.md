
To get the EOAM stack to work with the ONOS olt-test, the following
command was used in the shell to launch the olt-test.

NOTE: This command should soon be eliminated as the adapter should
be started by VOLTHA. By running the commands as listed below, then
the olt-test can take advantage of the virtual environment.

```
$ cd <LOCATION_OF_VOLTHA>
$ sudo -s
# . ./env.sh
(venv-linux) # PYTHONPATH=$HOME/dev/voltha/voltha/adapters/tibit ./oftest/oft --test-dir=olt-oftest/ -i 1@enp1s0f0 -i 2@enp1s0f1 --port 6633 -V 1.3 -t "olt_port=1;onu_port=2;in_out_port=1;device_type='tibit'" olt-complex.TestScenario1SingleOnu
```
