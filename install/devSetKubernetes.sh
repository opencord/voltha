#!/bin/bash

# This script is for development use.

echo 'cluster_framework="kubernetes"' >> install.cfg
echo 'cluster_service_subnet="192.168.0.0\/18"' >> install.cfg
echo 'cluster_pod_subnet="192.168.128.0\/18"' >> install.cfg
