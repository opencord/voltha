#!/bin/bash

cd /
nginx -c /nginx_config/nginx.conf&
sleep 2 # Let nginx get settled bfore starting consul-template to avoid attemtps to reload resulting in errors.
exec consul-template -reload-signal='SIGHUP' -consul $CONSUL_ADDR -template="nginx_config/nginx-upstreams.ctmpl:nginx_config/upstreams/voltha-upstreams.conf:nginx -s reload"
