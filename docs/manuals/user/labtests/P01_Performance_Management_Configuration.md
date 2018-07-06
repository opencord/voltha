# P01 - Performance management configuration

## Test objective

To demonstrate the ability to configure performance management using the *simulated-olt*.

* Demonstrate the ability to change the frequency with which the stats are sampled and posted to kafka
* Demonstrate the ability to selectively disable and enable specific stats
* Demonstrate how the stats can be queried.

## Test configuration

* The Voltha enseble is running per the deployment instructions.

## Test procedure

Start the voltha cli and add the simulated OLT.

```shell
 ./cli/main.py -L
         _ _   _            ___ _    ___
__ _____| | |_| |_  __ _   / __| |  |_ _|
\ V / _ \ |  _| ' \/ _` | | (__| |__ | |
 \_/\___/_|\__|_||_\__,_|  \___|____|___|
(to exit type quit or hit Ctrl-D)
(voltha)
```

Ensure that voltha is operating correctly:

```shell
health
```

```json
{
    "state": "HEALTHY"
}
```

Preprovision and enable the simulated OLT

```shell
(voltha) preprovision_olt
success (device id = eecd8f5327bc)
(voltha) enable
enabling eecd8f5327bc
waiting for device to be enabled...
success (logical device id = 1)
(voltha)
```

The device Id will be different from the device id shown above.

In a different window, verify that the simulated stats are now being posted to the Kafak bus. First determine the port hosting the kafka broker:

```shell
$ docker inspect compose_kafka_1 | jq -r '.[0].NetworkSettings.Ports["9092/tcp"][0]["HostPort"]'
32778
```

Using this port, query the kafka broker for topics

```shell
kafkacat -b localhost:32778 -L
Metadata for all topics (from broker -1: localhost:32778/bootstrap):
 1 brokers:
  broker 1001 at 10.0.2.15:32778
 5 topics:
  topic "voltha.alarms" with 1 partitions:
    partition 0, leader 1001, replicas: 1001, isrs: 1001
  topic "voltha.kpis" with 1 partitions:
    partition 0, leader 1001, replicas: 1001, isrs: 1001
  topic "voltha.events" with 1 partitions:
    partition 0, leader 1001, replicas: 1001, isrs: 1001
  topic "voltha.heartbeat" with 1 partitions:
    partition 0, leader 1001, replicas: 1001, isrs: 1001
```

The topic of interest for this test is the voltha.kpis topic. So now query the topic to ensure that the simulated OLT is generating stats.

```shell
kafkacat -b localhost:32778 -C -o -1 -c 1 -t voltha.kpis | jq '.prefixes'
```

```json
{
  "voltha.simulated_olt.eecd8f5327bc.pon": {
    "metrics": {
      "rx_256_511": 47629,
      "tx_128_255": 33976,
      "tx_256_511": 47606,
      "tx_bytes": 51704532,
      "rx_bytes": 51757379,
      "rx_pkts": 51646,
      "rx_128_255": 33901,
      "tx_64": 28552,
      "rx_64": 28590,
      "tx_pkts": 51668,
      "rx_1519_9k": 28502,
      "tx_512_1023": 50295,
      "rx_1024_1518": 33998,
      "tx_65_127": 31313,
      "rx_65_127": 31280,
      "tx_1519_9k": 28505,
      "tx_1024_1518": 34027,
      "rx_512_1023": 50307
    }
  },
  "voltha.simulated_olt.eecd8f5327bc": {
    "metrics": {
      "cpu_util": 24.542841249401473,
      "buffer_util": 18.404615469439612
    }
  },
  "voltha.simulated_olt.eecd8f5327bc.nni": {
    "metrics": {
      "rx_256_511": 47649,
      "tx_128_255": 34071,
      "tx_256_511": 47569,
      "tx_bytes": 51634215,
      "rx_bytes": 51665858,
      "rx_pkts": 51686,
      "rx_128_255": 34038,
      "tx_64": 28592,
      "rx_64": 28489,
      "tx_pkts": 51621,
      "rx_1519_9k": 28591,
      "tx_512_1023": 50345,
      "rx_1024_1518": 34075,
      "tx_65_127": 31255,
      "rx_65_127": 31238,
      "tx_1519_9k": 28546,
      "tx_1024_1518": 33967,
      "rx_512_1023": 50252
    }
  }
}
```

Once the generation of simulated statistics has been confirmed we validate how often the stats are being posted to kafka prior to the next step which is to change the frequency with which the stats are bing sampled. The following command will establish the sampling interval.

```shell
avg=0;last=0;for i in `kafkacat -b localhost:32778 -C -o -10 -c 10 -t voltha.kpis | grep 'simulated_olt' | jq -r '.ts'`; do if [ $last -eq 0 ]; then last=$i; else if [ $avg -eq 0 ]; then avg=`expr $i - $last`; else avg=`expr \( $avg + $i - $last \) \/ 2`; fi; last=$i; fi; done; echo $avg; unset avg; unset last
```

```shell
15
```

The default set by the simulated OLT is to pretend to sample metrics every 15 seconds and publish them to kafka. This can be changed by using the performance monitoring configuration functionality. Swithch back to the window running the voltha cli and enter device command mode for the simulated OLT.

```shell
(voltha) devices

+--------------+---------------+-------------------+-------------+-------------+----------------+
|           id |          type |       mac_address | admin_state | oper_status | connect_status |
+--------------+---------------+-------------------+-------------+-------------+----------------+
| eecd8f5327bc | simulated_olt | 00:0c:e2:31:40:00 |     ENABLED |      ACTIVE |      REACHABLE |
+--------------+---------------+-------------------+-------------+-------------+----------------+
```

Using the value in the id column, enter device command mode for the device
```shell
(voltha) device eecd8f5327bc
```

```shell
(device eecd8f5327bc)
```

Now display the current performance management configuration of the device. Your device id will be different than the one used throughout these examples.

```shell
(device eecd8f5327bc) perf_config
```

```shell
PM Config:
+---------------+-------+
|         field | value |
+---------------+-------+
|  default_freq |   150 |
|       grouped | False |
| freq_override | False |
+---------------+-------+

Supported metrics:
+--------------+---------+---------+
|         name | enabled |    type |
+--------------+---------+---------+
| rx_1024_1518 |    True | COUNTER |
|   rx_128_255 |    True | COUNTER |
|   rx_1519_9k |    True | COUNTER |
|   rx_256_511 |    True | COUNTER |
|  rx_512_1023 |    True | COUNTER |
|        rx_64 |    True | COUNTER |
|    rx_65_127 |    True | COUNTER |
|     rx_bytes |    True | COUNTER |
|      rx_pkts |    True | COUNTER |
| tx_1024_1518 |    True | COUNTER |
|   tx_128_255 |    True | COUNTER |
|   tx_1519_9k |    True | COUNTER |
|   tx_256_511 |    True | COUNTER |
|  tx_512_1023 |    True | COUNTER |
|        tx_64 |    True | COUNTER |
|    tx_65_127 |    True | COUNTER |
|     tx_bytes |    True | COUNTER |
|      tx_pkts |    True | COUNTER |
+--------------+---------+---------+
(device eecd8f5327bc)
```

As shown, the default_freq which is the sampling frequency is set to 150 10^ths^ of a second. View the help to determine how to change that.

```shell
(device eecd8f5327bc) help perf_config
```

```shell
perfo_config [show | set | commit | reset] [-f <default frequency>] [-e <metric/group name>] [-d <metric/group name>] [-o <metric/group name> <override frequency>]

Changes made by set are held locally until a commit or reset command is issued.
A commit command will write the configuration to the device and it takes effect
immediately. The reset command will undo any changes sinc the start of the
device session.

If grouped is true then the -d, -e and -o commands refer to groups and not
individual metrics.
(device eecd8f5327bc)
```

As shown in the help using set with the -f option will change the default_freq so lets set that to 5 seconds or 50 10^ths^ of a second.

```shell
(device eecd8f5327bc) perf_config set -f 50
```

```shell
Success
(device eecd8f5327bc)
```

Lets verify that the chnages have indeed been saved to the edit buffer.

```shell
(device eecd8f5327bc) perf_config show
```

```shell
PM Config:
+---------------+-------+
|         field | value |
+---------------+-------+
|  default_freq |    50 |
|       grouped | False |
| freq_override | False |
+---------------+-------+

Supported metrics:
+--------------+---------+---------+
|         name | enabled |    type |
+--------------+---------+---------+
| rx_1024_1518 |    True | COUNTER |
|   rx_128_255 |    True | COUNTER |
|   rx_1519_9k |    True | COUNTER |
|   rx_256_511 |    True | COUNTER |
|  rx_512_1023 |    True | COUNTER |
|        rx_64 |    True | COUNTER |
|    rx_65_127 |    True | COUNTER |
|     rx_bytes |    True | COUNTER |
|      rx_pkts |    True | COUNTER |
| tx_1024_1518 |    True | COUNTER |
|   tx_128_255 |    True | COUNTER |
|   tx_1519_9k |    True | COUNTER |
|   tx_256_511 |    True | COUNTER |
|  tx_512_1023 |    True | COUNTER |
|        tx_64 |    True | COUNTER |
|    tx_65_127 |    True | COUNTER |
|     tx_bytes |    True | COUNTER |
|      tx_pkts |    True | COUNTER |
+--------------+---------+---------+
(device eecd8f5327bc)
```

The default_freq is now set to 5o 10^ths^ of a second. This change has not been applied yet. In order to apply the change, it must be committed. Lets do that now.

```shell
(device eecd8f5327bc) perf_config commit
```

```shell
PM Config:
+---------------+-------+
|         field | value |
+---------------+-------+
|  default_freq |    50 |
|       grouped | False |
| freq_override | False |
+---------------+-------+

Supported metrics:
+--------------+---------+---------+
|         name | enabled |    type |
+--------------+---------+---------+
| rx_1024_1518 |    True | COUNTER |
|   rx_128_255 |    True | COUNTER |
|   rx_1519_9k |    True | COUNTER |
|   rx_256_511 |    True | COUNTER |
|  rx_512_1023 |    True | COUNTER |
|        rx_64 |    True | COUNTER |
|    rx_65_127 |    True | COUNTER |
|     rx_bytes |    True | COUNTER |
|      rx_pkts |    True | COUNTER |
| tx_1024_1518 |    True | COUNTER |
|   tx_128_255 |    True | COUNTER |
|   tx_1519_9k |    True | COUNTER |
|   tx_256_511 |    True | COUNTER |
|  tx_512_1023 |    True | COUNTER |
|        tx_64 |    True | COUNTER |
|    tx_65_127 |    True | COUNTER |
|     tx_bytes |    True | COUNTER |
|      tx_pkts |    True | COUNTER |
+--------------+---------+---------+
(device eecd8f5327bc) 
```

Now after waiting 30 seconds or so to ensure we don't average in any older sampling intervals let's go back to a linux window and check and see how often the metrics are being sampled.

```shell
voltha$ avg=0;last=0;for i in `kafkacat -b localhost:32778 -C -o -10 -c 10 -t voltha.kpis | grep 'simulated_olt' | jq -r '.ts'`; do if [ $last -eq 0 ]; then last=$i; else if [ $avg -eq 0 ]; then avg=`expr $i - $last`; else avg=`expr \( $avg + $i - $last \) \/ 2`; fi; last=$i; fi; done; echo $avg; unset avg; unset last 5
```

The change has taken effect and the metrics are now being sampled every 5 seconds. Now lets show how certain metrics can be disabled from the kafka output. Lets say that we no longer want to see any jumbo frame counters. Go back to the voltha cli window and get the help for the `perf_config` command again. Looking at the command using set with the -d options disables metrics and using the set command with -e options enables metrics. To disable both rx and tx metrics for 1519_9k issue the following command in the voltha cli.

```shell
(device eecd8f5327bc) perf_config set -d rx_1519_9k -d tx_1519_9k
```

```shell
Success
(device eecd8f5327bc)
```

Now view the configuration to validate that the requested changes have been applied to the edit buffer.

```shell
(device eecd8f5327bc) perf_config show
```

```shell
PM Config:
+---------------+-------+
|         field | value |
+---------------+-------+
|  default_freq |    50 |
|       grouped | False |
| freq_override | False |
+---------------+-------+

Supported metrics:
+--------------+---------+---------+
|         name | enabled |    type |
+--------------+---------+---------+
| rx_1024_1518 |    True | COUNTER |
|   rx_128_255 |    True | COUNTER |
|   rx_1519_9k |   False | COUNTER |
|   rx_256_511 |    True | COUNTER |
|  rx_512_1023 |    True | COUNTER |
|        rx_64 |    True | COUNTER |
|    rx_65_127 |    True | COUNTER |
|     rx_bytes |    True | COUNTER |
|      rx_pkts |    True | COUNTER |
| tx_1024_1518 |    True | COUNTER |
|   tx_128_255 |    True | COUNTER |
|   tx_1519_9k |   False | COUNTER |
|   tx_256_511 |    True | COUNTER |
|  tx_512_1023 |    True | COUNTER |
|        tx_64 |    True | COUNTER |
|    tx_65_127 |    True | COUNTER |
|     tx_bytes |    True | COUNTER |
|      tx_pkts |    True | COUNTER |
+--------------+---------+---------+
(device eecd8f5327bc)
```

The changes are there as expected. Now commit them using the commit command.

```shell
(device eecd8f5327bc) perf_config commit
```

```shell
PM Config:
+---------------+-------+
|         field | value |
+---------------+-------+
|  default_freq |    50 |
|       grouped | False |
| freq_override | False |
+---------------+-------+

Supported metrics:
+--------------+---------+---------+
|         name | enabled |    type |
+--------------+---------+---------+
| rx_1024_1518 |    True | COUNTER |
|   rx_128_255 |    True | COUNTER |
|   rx_1519_9k |   False | COUNTER |
|   rx_256_511 |    True | COUNTER |
|  rx_512_1023 |    True | COUNTER |
|        rx_64 |    True | COUNTER |
|    rx_65_127 |    True | COUNTER |
|     rx_bytes |    True | COUNTER |
|      rx_pkts |    True | COUNTER |
| tx_1024_1518 |    True | COUNTER |
|   tx_128_255 |    True | COUNTER |
|   tx_1519_9k |   False | COUNTER |
|   tx_256_511 |    True | COUNTER |
|  tx_512_1023 |    True | COUNTER |
|        tx_64 |    True | COUNTER |
|    tx_65_127 |    True | COUNTER |
|     tx_bytes |    True | COUNTER |
|      tx_pkts |    True | COUNTER |
+--------------+---------+---------+
(device eecd8f5327bc)
```

Now lets validate that the metrics that have been set to false will no longer be published to kafka. Moving back to the Linux window use the following command:

```shell
voltha$ kafkacat -b localhost:32778 -C -o -1 -c 1 -t voltha.kpis | jq '.prefixes'
```

```json
{
  "voltha.simulated_olt.eecd8f5327bc.pon": {
    "metrics": {
      "rx_256_511": 66994,
      "tx_128_255": 47787,
      "tx_256_511": 66965,
      "tx_pkts": 72684,
      "rx_bytes": 72795037,
      "rx_pkts": 72708,
      "rx_128_255": 47700,
      "tx_64": 40156,
      "rx_64": 40172,
      "tx_512_1023": 70724,
      "rx_1024_1518": 47800,
      "tx_65_127": 44018,
      "rx_65_127": 44011,
      "tx_bytes": 72736980,
      "tx_1024_1518": 47854,
      "rx_512_1023": 70773
    }
  },
  "voltha.simulated_olt.eecd8f5327bc": {
    "metrics": {
      "cpu_util": 23.933588409473266,
      "buffer_util": 12.861151886751806
    }
  },
  "voltha.simulated_olt.eecd8f5327bc.nni": {
    "metrics": {
      "rx_256_511": 67001,
      "tx_128_255": 47860,
      "tx_256_511": 66834,
      "tx_pkts": 72637,
      "rx_bytes": 72658405,
      "rx_pkts": 72718,
      "rx_128_255": 47833,
      "tx_64": 40188,
      "rx_64": 40123,
      "tx_512_1023": 70768,
      "rx_1024_1518": 47852,
      "tx_65_127": 43975,
      "rx_65_127": 43933,
      "tx_bytes": 72669736,
      "tx_1024_1518": 47736,
      "rx_512_1023": 70703
    }
  }
}
```

As expected both rx_1519_9k and tx_1519_9k are no longer being reported for any interface on the device.

This concludes this section of the test plan.

