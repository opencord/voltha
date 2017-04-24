#!/bin/bash

cd /
#nginx -c /nginx_config/nginx.conf&
exec consul-template -reload-signal='SIGHUP' -consul $CONSUL_ADDR -template="nginx_config/nginx-upstreams.ctmpl:nginx_config/upstreams/voltha-upstreams.conf:nginx -s reload"  -exec='/usr/sbin/nginx -c /nginx_config/nginx.conf -g "daemon off;"'
