#!/usr/bin/env python
import threading, logging, time

from kafka import KafkaConsumer

class Consumer(threading.Thread):
    daemon = True

    def run(self):
        consumer = KafkaConsumer(bootstrap_servers='10.100.198.220:9092',
                                 auto_offset_reset='earliest')
        consumer.subscribe(['voltha-heartbeat'])

        for message in consumer:
            print (message)


def main():
    threads = [
        Consumer()
    ]

    for t in threads:
        t.start()

    time.sleep(3000)

if __name__ == "__main__":
    main()

