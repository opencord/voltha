#!/bin/bash

# Initialize the OpenNMS environment and generate necessary configuration files
/docker-entrypoint.sh -i

# Replace default configuration with customized files
cp -r /tmp/opennms/etc/* /opt/opennms/etc

# Start OpenNMS
/docker-entrypoint.sh -f