#!/bin/bash
apt-get install -y curl unzip

mkdir -p /var/lib/consul
mkdir -p /usr/share/consul
mkdir -p /etc/consul/conf.d

consulVersion='0.9.2'

curl -OL https://releases.hashicorp.com/consul/${consulVersion}/consul_${consulVersion}_linux_amd64.zip
unzip consul_${consulVersion}_linux_amd64.zip
mv consul /usr/local/bin/consul
