# V4 - View Voltha Async Events with Kafkacat

## Test Objective

* Demonstrate and verify the async event stream (output) from Voltha

Voltha is sending asynchronous events to a Kafka "bus" system.
There are four types of events emitted by Kafka, using four separate Kafka
"topics":

* *heartbeat*: Voltha emits a periodic heart-beat through this channel. By default the Kafka topic name for this channel is *voltha.heartbeat*.
* *kpi/performance metrics*: Voltha uses this channel to send out consolidated performance metric data about its internal components as well as about the devices managed by Voltha. While the channel is live, the metrics are limited to a few sample metrics at the moment (work in progress).  By default the Kafka topic name for this channel is *voltha.kpis*.
* *alarms*: Voltha uses this channel to send out consolidated alarm signals, covering the devices it manages as well as alarms about its internal operation. This is not used yet, albeit the internal plumbing in Voltha exists. By default the Kafka topic name for this channel is *voltha/alarms*.
* events*: Voltha uses this channel to send out consolidated async events (other than alarms), covering the devices it manages as well as events about its internal operation. This is not used yet, albeit the internal plumbing in Voltha exists. By default the Kafka topic name for this channel is *voltha/events*.

In a production deployment it is expected that other subsystems will consume
these Kafka topics. 
Our goal here is to demonstrate and verify that Voltha is working as expected.

## Test Configuration

* Voltha ensemble is launched (V1)

## Test Procedure

In order to show the Kafka channels, we use a command line tool *kafkacat* to "tune into" the channels.
To run kafkacat we need to know the port number of the kafka broker. Use the following command to retrieve the assigned port to Kafka:

```shell
docker inspect compose_kafka_1 | jq -r '.[0].NetworkSettings.Ports["9092/tcp"][0]["HostPort"]'
```

For example, it may say:

```shell
32769
```

This is the port number Kafka is reacheable at the integration server.

To show the topics that have data, run the command (make sure you use the port number that you retreived in the above step):

```shell
kafkacat -b localhost:32769 -L
```

Here is what you should see:

```shell
(venv-linux) ubuntu@voltha:/voltha$ kafkacat -b localhost:32769 -L
Metadata for all topics (from broker -1: localhost:32769/bootstrap):
 1 brokers:
  broker 1001 at 10.0.2.15:32769
 2 topics:
  topic "voltha.kpis" with 1 partitions:
    partition 0, leader 1001, replicas: 1001, isrs: 1001
  topic "voltha.heartbeat" with 1 partitions:
    partition 0, leader 1001, replicas: 1001, isrs: 1001
```

There are only two topics shown from the four we described above. The reason
is that the other topics have no published data yet.

In order to show data published to the heartbeat channel, use the following
command (*Make sure you use the correct port number!*):

```shell
kafkacat -b localhost:32769 -C -t voltha.heartbeat -f 'Topic %t [%p] at offset %o: key %k: %s\n'
```

The above will show all existing data in the queue and will stay connected and print messages as they arrive ("tail" the channel). You can use Ctrl-C to interrupt the tailing and return to the Linux prompt.

Example output, showing only the first few lines:

```shell
(venv-linux) ubuntu@voltha:/voltha$ kafkacat -b localhost:32769 -C -t voltha.heartbeat -f 'Topic %t [%p] at offset %o: key %k: %s\n'
Topic voltha.heartbeat [0] at offset 0: key : {"ip": "172.18.0.9", "type": "heartbeat", "voltha_instance": "compose_voltha_1", "ts": 1484291374}
Topic voltha.heartbeat [0] at offset 1: key : {"ip": "172.18.0.9", "type": "heartbeat", "voltha_instance": "compose_voltha_1", "ts": 1484291384}
Topic voltha.heartbeat [0] at offset 2: key : {"ip": "172.18.0.9", "type": "heartbeat", "voltha_instance": "compose_voltha_1", "ts": 1484291394}
Topic voltha.heartbeat [0] at offset 3: key : {"ip": "172.18.0.9", "type": "heartbeat", "voltha_instance": "compose_voltha_1", "ts": 1484291404}
Topic voltha.heartbeat [0] at offset 4: key : {"ip": "172.18.0.9", "type": "heartbeat", "voltha_instance": "compose_voltha_1", "ts": 1484291414}
Topic voltha.heartbeat [0] at offset 5: key : {"ip": "172.18.0.9", "type": "heartbeat", "voltha_instance": "compose_voltha_1", "ts": 1484291424}
Topic voltha.heartbeat [0] at offset 6: key : {"ip": "172.18.0.9", "type": "heartbeat", "voltha_instance": "compose_voltha_1", "ts": 1484291434}
Topic voltha.heartbeat [0] at offset 7: key : {"ip": "172.18.0.9", "type": "heartbeat", "voltha_instance": "compose_voltha_1", "ts": 1484291444}
Topic voltha.heartbeat [0] at offset 8: key : {"ip": "172.18.0.9", "type": "heartbeat", "voltha_instance": "compose_voltha_1", "ts": 1484291454}
```

Similarly, you can watch KPI metrics as follows:

```shell
kafkacat -b localhost:32769 -C -t voltha.kpis -f 'Topic %t [%p] at offset %o: key %k: %s\n'
```

This may show only two Voltha metrics, yet it still verifies the proper operation of the KPI metric collection mechanism. A sample output is as follows, truncated to only the first 15 lines:
 
```shell
(venv-linux) ubuntu@voltha:/voltha$ kafkacat -b localhost:32769 -C -t voltha.kpis -f 'Topic %t [%p] at offset %o: key %k: %s\n'
Topic voltha.kpis [0] at offset 0: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 20, "rss-mb": 79}}, "type": "slice", "ts": 1484291374}
Topic voltha.kpis [0] at offset 1: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291389}
Topic voltha.kpis [0] at offset 2: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291404}
Topic voltha.kpis [0] at offset 3: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291419}
Topic voltha.kpis [0] at offset 4: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291434}
Topic voltha.kpis [0] at offset 5: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291449}
Topic voltha.kpis [0] at offset 6: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291464}
Topic voltha.kpis [0] at offset 7: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291479}
Topic voltha.kpis [0] at offset 8: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291494}
Topic voltha.kpis [0] at offset 9: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291509}
Topic voltha.kpis [0] at offset 10: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291524}
Topic voltha.kpis [0] at offset 11: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291539}
Topic voltha.kpis [0] at offset 12: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291554}
Topic voltha.kpis [0] at offset 13: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291569}
Topic voltha.kpis [0] at offset 14: key : {"data": {"voltha.internal.compose_voltha_1": {"deferreds": 173, "rss-mb": 79}}, "type": "slice", "ts": 1484291584}
```

## Pass/Fail Criteria

* The above feeds (topics) should exist in Kafka and have data in both topics.
